<template>
  <div>
    <a-space size="large">
      <h2>客户端</h2>
      <NuxtLink to="/">
        回主页
      </NuxtLink>
    </a-space>
    <div>
      <h3>ID: {{ client.id }}</h3>
      <h3>备注: {{ client.comment }}</h3>
    </div>
    <div>
      <a-button type="primary" @click="show_add_tcp = true">
        添加TCP转发
      </a-button>
    </div>
    <a-modal v-model="show_add_tcp" title="添加TCP转发" :footer="null">
      <a-form-model>
        <a-form-model-item label="外部端口">
          <a-input-number v-model="new_tcp_forward.listen_port" />
        </a-form-model-item>
        <a-form-model-item label="内部地址">
          <a-input v-model="new_tcp_forward.forward_client_ip" />
        </a-form-model-item>
        <a-form-model-item label="内部端口">
          <a-input-number
            v-model="new_tcp_forward.forward_client_port"
          />
        </a-form-model-item>
        <a-form-model-item label="备注">
          <a-input v-model="new_tcp_forward.comment" />
        </a-form-model-item>
        <a-form-model-item>
          <a-button type="primary" @click="onCreate">
            添加
          </a-button>
        </a-form-model-item>
      </a-form-model>
    </a-modal>
    <br>
    <a-table
      :columns="columns"
      :data-source="client.tcp_forwards || []"
      :bordered="true"
    >
      <span slot="action" slot-scope="record">
        <a-button
          type="danger"
          size="small"
          @click="onDelete(record.listen_port)"
        >
          删除
        </a-button>
      </span>
    </a-table>
  </div>
</template>

<script>
import auth_mixin from '../auth_mixin';

const columns = [
    {
        title: '外部端口',
        dataIndex: 'listen_port'
    },
    {
        title: '内部地址',
        dataIndex: 'forward_client_ip'
    },
    {
        title: '内部端口',
        dataIndex: 'forward_client_port'
    },
    {
        title: '备注',
        dataIndex: 'comment'
    },
    {
        title: '操作',
        scopedSlots: { customRender: 'action' }
    }
];
export default {
    mixins: [auth_mixin],
    data () {
        return {
            client: {},
            columns,
            show_add_tcp: false,
            new_tcp_forward: {
                client_id: '',
                listen_port: 0,
                forward_client_ip: '',
                forward_client_port: 0,
                comment: ''
            }
        };
    },
    async created () {
        if (!(await this.IsAdminLogined())) {
            this.$router.replace('/login');
            return;
        }
        this.update();
    },
    methods: {
        async update () {
            const res = await this.$http.get('/api/admin/data');
            for (const client of res.data.clients) {
                if (client.id === this.$route.params.client_id) {
                    this.client = client;
                }
            }
            this.new_tcp_forward.client_id = this.$route.params.client_id;
        },
        async onCreate () {
            await this.$http.post(
                '/api/admin/new_tcp_forward',
                {},
                this.new_tcp_forward
            );
            this.$message.success('创建成功');
            this.show_add_tcp = false;
            this.update();
        },
        async onDelete (listen_port) {
            this.$confirm({
                title: '确认删除？',
                content: '确认删除？',
                onOk: async () => {
                    await this.$http.post(
                        '/api/admin/delete_tcp_forward',
                        {},
                        { client_id: this.client.id, listen_port }
                    );
                    this.$message.success('删除成功');
                    this.update();
                },
                onCancel () {}
            });
        }
    }
};
</script>
