const fs = require('fs');
const path = require('path');
const assert = require('assert');
const net = require('net');
const Router = require('koa-router');
const utility = require('utility');
const moment = require('moment');
const _ = require('lodash');
const config = require('../config');

const router = module.exports = new Router();

// ============ ADMIN ===============
// header: AdminAuth
function GenAdminAuth () {
    const data = {
        is_admin: true,
        password_sha1: utility.hmac('sha1', config.SERVER.SECRET_KEYS, config.ADMIN_PASSWORD, 'base64'),
        expire: moment().add(moment.duration(1, 'day')).unix() * 1000
    };
    const data_s = JSON.stringify(data);
    const sign = utility.hmac('sha1', config.SERVER.SECRET_KEYS, data_s, 'base64');
    const auth_data = {
        data_s, sign
    };
    return utility.base64encode(JSON.stringify(auth_data));
}
function IsAdminAuthed (ctx) {
    try {
        const AdminAuth = ctx.req.headers.adminauth;
        if (!AdminAuth) { return false; }
        const { data_s, sign } = JSON.parse(utility.base64decode(AdminAuth));
        if (utility.hmac('sha1', config.SERVER.SECRET_KEYS, data_s, 'base64') !== sign) { return false; }
        const data = JSON.parse(data_s);
        if (!data.is_admin || moment(data.expire).isBefore(moment())) { return false; }
        if (utility.hmac('sha1', config.SERVER.SECRET_KEYS, config.ADMIN_PASSWORD, 'base64') !== data.password_sha1) { return false; }
        return true;
    } catch (e) {
        return false;
    }
}
async function AdminRequired (ctx, next) {
    assert(IsAdminAuthed(ctx), '尚未登录');
    await next();
}

router.get('/admin/admin_status', async (ctx) => {
    ctx.body = {
        success: true,
        is_admin: IsAdminAuthed(ctx)
    };
});

// password
router.post('/admin/login', async (ctx) => {
    const password = ctx.request.body.password;
    assert(config.ADMIN_PASSWORD, '没有设置密码');
    assert(password === config.ADMIN_PASSWORD, '密码不正确');
    ctx.body = {
        success: true,
        admin_auth: GenAdminAuth()
    };
});

router.post('/admin/renew_auth', AdminRequired, async (ctx) => {
    ctx.body = {
        success: true,
        admin_auth: GenAdminAuth()
    };
});

const DATA_PATH = path.resolve(__dirname, '..', '..', 'data.json');
let data = { clients: [] };
/**
 * {
 *  clients: [{
 *      id: string,
 *      key: string,
 *      comment: string,
 *      online?: bool,
 *      tcp_forwards?: [{
 *          listen_port: int,
 *          forward_client_ip: string,
 *          forward_client_port: int,
 *          comment: string
 *      }]
 *  }]
 * }
 */
let status = null;
let need_push_config = false;

if (fs.existsSync(DATA_PATH)) {
    data = JSON.parse(fs.readFileSync(DATA_PATH, 'utf-8'));
}

router.get('/admin/data', AdminRequired, async (ctx) => {
    const send_data = _.cloneDeep(data);
    for (const client of send_data.clients) {
        client.online = false;
        if (status) {
            client.online = _.includes(status.online_clients || [], client.id);
        }
    }
    ctx.body = {
        success: true,
        data: send_data
    };
});

router.post('/admin/new_client', AdminRequired, async (ctx) => {
    const id = ctx.request.body.id;
    const comment = ctx.request.body.comment;
    assert(_.isString(id));
    assert(id);

    for (const client of data.clients) {
        assert(client.id !== id, 'ID已存在');
    }

    const key = utility.randomString(10, '1234567890');
    data.clients.push({
        id, key, comment
    });
    fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 4));
    need_push_config = true;

    ctx.body = {
        success: true
    };
});

router.post('/admin/delete_client', AdminRequired, async (ctx) => {
    const id = ctx.request.body.id;
    assert(_.isString(id));
    assert(id);
    assert(_.some(data.clients, c => c.id === id), 'ID不存在');

    data.clients = data.clients.filter(c => c.id !== id);
    fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 4));
    need_push_config = true;

    ctx.body = {
        success: true
    };
});

router.post('/admin/new_tcp_forward', AdminRequired, async (ctx) => {
    const client_id = ctx.request.body.client_id;
    const listen_port = ctx.request.body.listen_port;
    const forward_client_ip = ctx.request.body.forward_client_ip;
    const forward_client_port = ctx.request.body.forward_client_port;
    const comment = ctx.request.body.comment;
    assert(_.isString(client_id));
    assert(client_id);
    assert(_.isInteger(listen_port));
    assert(listen_port);
    assert(_.isString(forward_client_ip));
    assert(forward_client_ip);
    assert(_.isInteger(forward_client_port));
    assert(forward_client_port);

    assert(_.some(data.clients, c => c.id === client_id), 'ID不存在');

    for (const client of data.clients) {
        if (client.tcp_forwards) {
            for (const forward of client.tcp_forwards) {
                assert(forward.listen_port !== listen_port, '重复端口');
            }
        }
    }

    let c = null;
    for (const client of data.clients) {
        if (client.id === client_id) {
            c = client;
        }
    }
    assert(c);
    if (!c.tcp_forwards) { c.tcp_forwards = []; }
    c.tcp_forwards.push({
        listen_port,
        forward_client_ip,
        forward_client_port,
        comment
    });
    fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 4));
    need_push_config = true;

    ctx.body = {
        success: true
    };
});

router.post('/admin/delete_tcp_forward', AdminRequired, async (ctx) => {
    const client_id = ctx.request.body.client_id;
    const listen_port = ctx.request.body.listen_port;
    assert(_.isString(client_id));
    assert(client_id);
    assert(_.isInteger(listen_port));
    assert(listen_port);

    assert(_.some(data.clients, c => c.id === client_id), 'ID不存在');

    let c = null;
    for (const client of data.clients) {
        if (client.id === client_id) {
            c = client;
        }
    }
    assert(c);
    assert(_.some(c.tcp_forwards || [], forward => forward.listen_port === listen_port), '端口不存在');
    if (!c.tcp_forwards) { c.tcp_forwards = []; }
    c.tcp_forwards = c.tcp_forwards.filter(forward => forward.listen_port !== listen_port);
    fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 4));
    need_push_config = true;

    ctx.body = {
        success: true
    };
});

// =============== STATUS ================

function PushConfig () {
    return new Promise((resolve, reject) => {
        const s = net.connect(config.MANAGE_SOCK_PATH, () => {
            const config_json = {
                clients: [],
                tcp_forwards: []
            };
            for (const client of data.clients) {
                config_json.clients.push({
                    id: client.id,
                    key: client.key
                });
                for (const forward of (client.tcp_forwards || [])) {
                    config_json.tcp_forwards.push({
                        client_id: client.id,
                        listen_port: forward.listen_port,
                        forward_client_ip: forward.forward_client_ip,
                        forward_client_port: forward.forward_client_port
                    });
                }
            }
            s.write(`CONFIG ${JSON.stringify(config_json)}\n`);
            s.on('data', (chunk) => {
                s.end();
                const res = chunk.toString('utf-8').trim();
                if (res === 'CONFIG_OK') {
                    resolve();
                } else {
                    reject(new Error(res));
                }
            });
        });
        s.on('error', (err) => {
            s.end();
            reject(err);
        });
    });
}

function FetchStatus () {
    return new Promise((resolve, reject) => {
        const s = net.connect(config.MANAGE_SOCK_PATH, () => {
            s.write('FETCH_STATUS\n');
            s.on('data', (chunk) => {
                s.end();
                const res = chunk.toString('utf-8').trim();
                if (res.startsWith('STATUS')) {
                    resolve(JSON.parse(res.substr(res.indexOf(' ') + 1)));
                } else {
                    reject(new Error(res));
                }
            });
        });
        s.on('error', (err) => {
            s.end();
            reject(err);
        });
    });
}

function sleep (ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function ManageLoop () {
    while (true) {
        if (need_push_config) {
            need_push_config = false;
            await PushConfig();
        }

        const new_status = await FetchStatus();
        if (!status || status.startup_time !== new_status.startup_time) {
            await PushConfig();
        }
        status = new_status;

        await sleep(1000);
    }
}

(async () => {
    try {
        await ManageLoop();
    } catch (e) {
        console.error(e);
    }
    process.exit(1);
})();
