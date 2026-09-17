//! Async driver for schema-walker recursion.
//!
//! Ordinary recursive walks cost a native stack frame per nesting level.
//! On `wasm32` that stack is the host thread's (~1 MiB main, half on a
//! worker); overflowing it throws a `RangeError` that skips wasm
//! epilogues and leaves the instance trapped on the next call.
//!
//! Walkers are therefore `async fn`s. Steps that would recurse hand a
//! task to the driver via [`run_above`] and suspend; the driver polls
//! the task stack so the native stack holds only one task's inline
//! chain, never the document nesting. Tasks form a stack (innermost
//! last); only the innermost is polled, so shared walker state matches
//! ordinary recursion.

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

/// One walk task: a future the driver runs to completion above its requester.
pub(crate) type Task<'v> = Pin<Box<dyn Future<Output = ()> + 'v>>;

/// Channel for a suspending task to request one task above it.
///
/// At most one request per suspension; the driver takes it immediately,
/// so the channel never holds more than one.
pub(crate) struct Spawner<'v>(Rc<RefCell<Option<Task<'v>>>>);

impl<'v> Clone for Spawner<'v> {
    fn clone(&self) -> Self {
        Spawner(Rc::clone(&self.0))
    }
}

impl<'v> Spawner<'v> {
    pub(crate) fn new() -> Self {
        Spawner(Rc::new(RefCell::new(None)))
    }

    fn request(&self, task: Task<'v>) {
        let previous = self.0.borrow_mut().replace(task);
        debug_assert!(
            previous.is_none(),
            "a task requested a second task before suspending"
        );
    }

    fn take(&self) -> Option<Task<'v>> {
        self.0.borrow_mut().take()
    }
}

/// Future that suspends once and resumes on the next poll.
struct Suspend {
    resumed: bool,
}

impl Future for Suspend {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        if self.resumed {
            return Poll::Ready(());
        }
        self.resumed = true;
        Poll::Pending
    }
}

/// Run `root` and every requested descendant task to completion.
///
/// Push on request-after-suspend; pop on Ready and resume the task below.
fn drive<'v>(spawner: &Spawner<'v>, root: Task<'v>) {
    let mut tasks: Vec<Task<'v>> = vec![root];
    let mut cx = Context::from_waker(Waker::noop());

    while let Some(innermost) = tasks.last_mut() {
        match innermost.as_mut().poll(&mut cx) {
            Poll::Ready(()) => {
                tasks.pop();
            }
            Poll::Pending => match spawner.take() {
                Some(task) => tasks.push(task),
                None => unreachable!("a task suspended without requesting a task to run above it"),
            },
        }
    }
}

/// Run `task` as its own driver root and return what it produced.
///
/// The driver loop sits on the caller's stack for the whole walk, so a
/// nested walk (e.g. a `.cbor` payload) costs one native frame per open
/// payload — hence the open-payload bound.
pub(crate) fn run_root<'v, R: 'v>(spawner: &Spawner<'v>, task: impl Future<Output = R> + 'v) -> R {
    let slot: Rc<RefCell<Option<R>>> = Rc::new(RefCell::new(None));
    let sink = Rc::clone(&slot);

    drive(
        spawner,
        Box::pin(async move {
            let produced = task.await;
            *sink.borrow_mut() = Some(produced);
        }),
    );

    let produced = slot.borrow_mut().take();
    produced.expect("the root task of the walk has completed")
}

/// Request `task` above the caller and return a future that awaits its result.
///
/// Boxed and requested before the caller suspends so the waiting future
/// is pointer-sized; await before requesting again (one request per
/// suspension).
pub(crate) fn run_above<'v, R: 'v>(
    spawner: &Spawner<'v>,
    task: impl Future<Output = R> + 'v,
) -> impl Future<Output = R> + 'v {
    let slot: Rc<RefCell<Option<R>>> = Rc::new(RefCell::new(None));
    let sink = Rc::clone(&slot);

    spawner.request(Box::pin(async move {
        let produced = task.await;
        *sink.borrow_mut() = Some(produced);
    }));

    async move {
        Suspend { resumed: false }.await;

        let produced = slot.borrow_mut().take();
        produced.expect("the task run above this one has completed")
    }
}

#[cfg(test)]
mod tests {
    use super::{run_above, run_root, Spawner};

    /// Many stacked tasks on a thread too small for that much ordinary recursion.
    #[test]
    fn a_chain_of_tasks_costs_no_stack_per_task() {
        fn descend<'v>(
            spawner: &Spawner<'v>,
            levels: usize,
        ) -> impl std::future::Future<Output = usize> + 'v {
            let spawner = spawner.clone();
            async move {
                if levels == 0 {
                    return 0;
                }
                let below = run_above(&spawner, descend(&spawner, levels - 1)).await;
                below + 1
            }
        }
        let counted = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(|| {
                let spawner = Spawner::new();
                run_root(&spawner, descend(&spawner, 100_000))
            })
            .expect("failed to spawn the probe thread")
            .join()
            .expect("the chain did not hold");
        assert_eq!(counted, 100_000);
    }

    /// Innermost completes first; the outer resumes with the inner's result.
    #[test]
    fn a_task_resumes_with_what_the_task_above_it_produced() {
        let order = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let spawner = Spawner::new();
        let out = run_root(&spawner, {
            let spawner = spawner.clone();
            let order = std::rc::Rc::clone(&order);
            async move {
                order.borrow_mut().push("outer before");
                let inner = run_above(&spawner, {
                    let order = std::rc::Rc::clone(&order);
                    async move {
                        order.borrow_mut().push("inner");
                        42
                    }
                })
                .await;
                order.borrow_mut().push("outer after");
                inner + 1
            }
        });
        assert_eq!(out, 43);
        assert_eq!(
            *order.borrow(),
            vec!["outer before", "inner", "outer after"]
        );
    }
}
