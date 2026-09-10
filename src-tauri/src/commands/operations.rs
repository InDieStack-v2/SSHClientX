#[allow(dead_code)]
pub(crate) fn command_error(scope: &str, message: impl std::fmt::Display) -> String {
    format!("[{scope}] {message}")
}
#[allow(dead_code)]
pub(crate) fn local_path_error(message: impl std::fmt::Display) -> String {
    command_error("FILE", message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_prefixed_operation_errors() {
        assert_eq!(local_path_error("outside root"), "[FILE] outside root");
    }
}
