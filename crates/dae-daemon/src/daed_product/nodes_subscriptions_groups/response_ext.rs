use super::*;
impl HttpResponse {
    pub(in crate::daed_product) fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }
}
