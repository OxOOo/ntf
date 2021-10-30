<template>
  <div>
    <a-space size="large">
      <h2>客户端列表</h2>
      <a-button type="primary" @click="show_add = true">
        添加
      </a-button>
    </a-space>
    <a-modal v-model="show_add" title="添加客户端" :footer="null">
      <a-form-model>
        <a-form-model-item label="ID">
          <a-input v-model="new_client_id" />
        </a-form-model-item>
        <a-form-model-item label="备注">
          <a-input v-model="new_client_comment" />
        </a-form-model-item>
        <a-form-model-item>
          <a-button type="primary" @click="onCreate">
            添加
          </a-button>
        </a-form-model-item>
      </a-form-model>
    </a-modal>
    <a-table :columns="columns" :data-source="clients" :bordered="true">
      <span slot="online" slot-scope="record">
        <a-tag v-if="record.online" color="green"> 是 </a-tag>
        <a-tag v-else color="volcano"> 否 </a-tag>
      </span>
      <span slot="tcp_forwards" slot-scope="tcp_forwards">
        {{ (tcp_forwards || []).length }}
      </span>
      <span slot="action" slot-scope="record">
        <a-button size="small">
          <NuxtLink :to="'/client/' + record.id">打开</NuxtLink>
        </a-button>
        <a-button
          type="danger"
          size="small"
          @click="onDelete(record.id)"
        >
          删除
        </a-button>
      </span>
    </a-table>
  </div>
</template>

<script>
import auth_mixin from './auth_mixin';

const columns = [
    {
        title: 'ID',
        dataIndex: 'id'
    },
    {
        title: 'KEY',
        dataIndex: 'key'
    },
    {
        title: '在线',
        scopedSlots: { customRender: 'online' }
    },
    {
        title: '备注',
        dataIndex: 'comment'
    },
    {
        title: 'TCP转发',
        scopedSlots: { customRender: 'tcp_forwards' }
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
            clients: [],
            columns,
            show_add: false,
            new_client_id: '',
            new_client_comment: ''
        };
    },
    async created () {
        if (!(await this.IsAdminLogined())) {
            this.$router.replace('/login');
        }
        this.update();
        setInterval(() => {
            this.update();
        }, 2000);
    },
    methods: {
        async update () {
            const res = await this.$http.get('/api/admin/data');
            this.clients = res.data.clients;
        },
        async onCreate () {
            await this.$http.post(
                '/api/admin/new_client',
                {},
                {
                    id: this.new_client_id,
                    comment: this.new_client_comment
                }
            );
            this.$message.success('创建成功');
            this.show_add = false;
            this.update();
        },
        async onDelete (client_id) {
            this.$confirm({
                title: '确认删除？',
                content: '确认删除？',
                onOk: async () => {
                    await this.$http.post(
                        '/api/admin/delete_client',
                        {},
                        { id: client_id }
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
