use cardano_serialization_lib as csl;

pub(crate) fn pp_cost_model_to_csl(pp_cost_model: &Vec<i64>) -> csl::CostModel {
    let mut cost_model = csl::CostModel::new();
    for (i, cost) in pp_cost_model.iter().enumerate() {
        // `unsigned_abs` holds for `i64::MIN`, where `abs` overflows.
        let magnitude = csl::BigNum::from(cost.unsigned_abs());
        if *cost < 0 {
            #[allow(unused_must_use)]
            cost_model.set(i, &csl::Int::new_negative(&magnitude));
        } else {
            #[allow(unused_must_use)]
            cost_model.set(i, &csl::Int::new(&magnitude));
        }
    }
    cost_model
}