impl HttpResponse {
    fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }
}
