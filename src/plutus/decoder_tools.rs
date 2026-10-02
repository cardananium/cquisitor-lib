use blst::{blst_fp2, blst_p2};
use pallas_primitives::conway::{Constr, PlutusData};
use serde_json::{json, Value};
use uplc::ast::{Constant, NamedDeBruijn, Program, Term, Type};

pub fn to_json_program(program: &Program<NamedDeBruijn>) -> Value {
    let (major, minor, patch) = program.version;
    json!({
        "program": {
            "version": format!("{}.{}.{}", major, minor, patch),
            "term": to_json_term(&program.term),
        }
    })
}

pub fn to_json_term(term: &Term<NamedDeBruijn>) -> Value {
    match term {
        Term::Var(name) => json!({ "var": name.text }),
        Term::Delay(inner) => json!({ "delay": to_json_term(inner) }),
        Term::Lambda { parameter_name, body } => json!({
            "lambda": {
                "parameter_name": parameter_name.text,
                "body": to_json_term(body),
            }
        }),
        Term::Apply { function, argument } => json!({
            "apply": {
                "function": to_json_term(function),
                "argument": to_json_term(argument),
            }
        }),
        Term::Constant(constant) => json!({ "constant": to_json_constant(constant) }),
        Term::Force(inner) => json!({ "force": to_json_term(inner) }),
        Term::Error => json!({ "error": "error" }),
        Term::Builtin(builtin) => json!({ "builtin": builtin.to_string() }),
        Term::Constr { tag, fields } => json!({
            "constr": {
                "tag": tag,
                "fields": fields.iter().map(to_json_term).collect::<Vec<_>>(),
            }
        }),
        Term::Case { constr, branches } => json!({
            "case": {
                "constr": to_json_term(constr),
                "branches": branches.iter().map(to_json_term).collect::<Vec<_>>(),
            }
        }),
    }
}

fn to_json_constant(constant: &Constant) -> Value {
    match constant {
        Constant::Integer(i) => json!({ "integer": i.to_string() }),
        Constant::ByteString(bs) => json!({ "bytestring": hex::encode(bs) }),
        Constant::String(s) => json!({ "string": s }),
        Constant::Unit => json!({ "unit": "()" }),
        Constant::Bool(b) => json!({ "bool": b }),
        Constant::ProtoList(ty, items) => json!({
            "list": {
                "type": to_json_type(ty),
                "items": items.iter().map(|item| to_json_constant(item)).collect::<Vec<_>>(),
            }
        }),
        Constant::ProtoPair(left_type, right_type, left, right) => json!({
            "pair": {
                "type_left": to_json_type(left_type),
                "type_right": to_json_type(right_type),
                "left": to_json_constant(left),
                "right": to_json_constant(right),
            }
        }),
        Constant::Data(d) => json!({ "data": to_json_plutus_data(d) }),
        Constant::Bls12_381G1Element(p1) => json!({
            "bls12_381_G1_element": {
                "x": p1.x.l,
                "y": p1.y.l,
                "z": p1.z.l,
            }
        }),
        Constant::Bls12_381G2Element(p2) => json!({
            "bls12_381_G2_element": json_blst_p2(p2),
        }),
        // Bls12_381MlResult is an opaque Miller-loop result and has no canonical
        // serialized form; surface it as an error string rather than panicking.
        Constant::Bls12_381MlResult(_) => {
            json!({ "bls12_381_mlresult": "<not serializable>" })
        }
        Constant::Value(value) => json!({ "value": to_json_value(value) }),
    }
}

// Quantities are rendered as decimal strings: they are signed 128-bit and do
// not fit a JSON number losslessly.
fn to_json_value(value: &uplc::ast::Value) -> Value {
    Value::Array(
        value
            .clone()
            .into_entries()
            .into_iter()
            .map(|(currency, tokens)| {
                json!({
                    "currency_symbol": hex::encode(currency),
                    "tokens": tokens
                        .into_iter()
                        .map(|(token, quantity)| json!({
                            "token_name": hex::encode(token),
                            "quantity": quantity.to_string(),
                        }))
                        .collect::<Vec<_>>(),
                })
            })
            .collect(),
    )
}

fn json_blst_p2(p2: &blst_p2) -> Value {
    json!({
        "x": to_json_blst_fp2(&p2.x),
        "y": to_json_blst_fp2(&p2.y),
        "z": to_json_blst_fp2(&p2.z),
    })
}

fn to_json_blst_fp2(fp2: &blst_fp2) -> Value {
    Value::Array(fp2.fp.iter().map(|fp| json!(fp.l)).collect())
}

fn to_json_plutus_data(data: &PlutusData) -> Value {
    match data {
        PlutusData::Constr(Constr { tag, any_constructor, fields }) => json!({
            "constr": {
                "tag": tag,
                "any_constructor": any_constructor,
                "fields": fields.iter().map(to_json_plutus_data).collect::<Vec<_>>(),
            }
        }),
        PlutusData::Map(kvp) => json!({
            "map": kvp.iter().map(|(key, value)| json!({
                "key": to_json_plutus_data(key),
                "value": to_json_plutus_data(value),
            })).collect::<Vec<_>>()
        }),
        PlutusData::BigInt(bi) => json!({ "integer": bi }),
        PlutusData::BoundedBytes(bs) => json!({ "bytestring": hex::encode(bs.to_vec()) }),
        PlutusData::Array(a) => json!({
            "list": a.iter().map(to_json_plutus_data).collect::<Vec<_>>()
        }),
    }
}

fn to_json_type(term_type: &Type) -> Value {
    match term_type {
        Type::Bool => json!("bool"),
        Type::Integer => json!("integer"),
        Type::String => json!("string"),
        Type::ByteString => json!("bytestring"),
        Type::Unit => json!("unit"),
        Type::List(ty) => json!({ "list": to_json_type(ty) }),
        Type::Pair(left, right) => json!({
            "pair": {
                "left": to_json_type(left),
                "right": to_json_type(right),
            }
        }),
        Type::Data => json!("data"),
        Type::Bls12_381G1Element => json!("bls12_381_G1_element"),
        Type::Bls12_381G2Element => json!("bls12_381_G2_element"),
        Type::Bls12_381MlResult => json!("bls12_381_mlresult"),
        Type::Value => json!("value"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_constant_renders_entries_with_string_quantities() {
        let value = uplc::ast::Value::from_canonical_bounded_entries(vec![(
            vec![0xaa],
            vec![(vec![0xbb], -5), (vec![0xcc], i128::MAX)],
        )])
        .unwrap();
        assert_eq!(
            to_json_constant(&Constant::Value(value)),
            json!({ "value": [{
                "currency_symbol": "aa",
                "tokens": [
                    { "token_name": "bb", "quantity": "-5" },
                    { "token_name": "cc", "quantity": i128::MAX.to_string() },
                ],
            }]})
        );
        assert_eq!(to_json_type(&Type::Value), json!("value"));
    }
}
