<template>
  <div>
    <a-form-model :label-col="labelCol" :wrapper-col="wrapperCol">
      <a-form-model-item label="密码">
        <a-input-password v-model="password" />
      </a-form-model-item>
      <a-form-model-item :wrapper-col="{ span: 14, offset: 4 }">
        <a-button type="primary" @click="onSubmit">
          登录
        </a-button>
      </a-form-model-item>
    </a-form-model>
  </div>
</template>

<script>
import auth_mixin from './auth_mixin';

export default {
    mixins: [auth_mixin],
    data () {
        return {
            labelCol: { span: 4 },
            wrapperCol: { span: 14 },
            password: ''
        };
    },
    methods: {
        async onSubmit () {
            await this.AdminLogin(this.password);
            this.$message.success('登录成功');
            this.$router.push('/');
        }
    }
};
</script>
