export default {
    methods: {
        async IsAdminLogined () {
            const res = await this.$http.get('/api/admin/admin_status');
            return res.is_admin;
        },
        async AdminLogin (password) {
            const res = await this.$http.post('/api/admin/login', {}, { password });
            this.$http.setAdminAuth(res.admin_auth);
        }
    }
};
