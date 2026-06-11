#[cfg(test)]
mod native_live_matrix_tests {
    use super::super::*;

    #[test]
    fn native_live_matrix_records_resident_dataplane_production_admission_row() {
        let matrix = production_runtime_live_matrix_json(
            true, true, true, true, true, true, true, true, true, true, true, true, true, true,
            true, true, true, true, true, true, true, true, false,
        );

        assert!(!matrix["matrix_complete"].as_bool().unwrap());
        assert!(
            matrix["remaining_rows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| { row.as_str().unwrap() == "resident-userspace-dataplane-admission" })
        );
    }
}
