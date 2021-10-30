import axios from 'axios';
import { Modal } from 'ant-design-vue';
import Cookie from 'js-cookie';

const baseURL = '/';

const instance = axios.create({
    baseURL,
    timeout: 10000,
    withCredentials: true
});

function showModel (type, title, content) {
    return new Promise((resolve) => {
        setTimeout(() => {
            Modal.destroyAll();
            Modal[type]({
                title,
                content,
                onOk: () => {
                    resolve();
                }
            });
        }, 500);
    });
}

function never () {
    return new Promise(() => { });
}

async function handle (req) {
    let data = {};
    try {
        const res = await req;
        data = res.data;
    } catch (e) {
        await showModel('error', '网络错误', e.message);
        // throw e; // IE上会弹出错误提示
        await never();
    }
    if (!data.success) {
        await showModel('info', '错误', data.message);
        // throw new Error(data.message);
        await never();
    }
    return data;
}

class Http {
    constructor () {
        this.baseURL = baseURL;
    }

    getCookie (key) {
        if (process.server) {
            if (!this.req.headers.cookie) {
                return null;
            }
            const rawCookie = this.req.headers.cookie
                .split(';')
                .find(c => c.trim().startsWith(`${key}=`));
            if (!rawCookie) {
                return null;
            }
            return rawCookie.split('=')[1];
        } else {
            return Cookie.get(key) || null;
        }
    }

    getAuthHeaders () {
        return {
            AdminAuth: this.getCookie('AdminAuth') || ''
        };
    }

    setAdminAuth (token) {
        Cookie.set('AdminAuth', token);
    }

    async get (url, params) {
        params = params || {};
        return await handle(instance.get(url, { params, headers: this.getAuthHeaders() }));
    }

    async post (url, params, data) {
        params = params || {};
        data = data || {};
        return await handle(instance.post(url, data, { params, headers: this.getAuthHeaders() }));
    }
}

export default ({ req }, inject) => {
    inject('http', new Http({}));
};
