// 网站

const path = require('path');
const mount = require('koa-mount');
const Koa = require('koa');
const Router = require('koa-router');
const bodyParser = require('koa-bodyparser');
const _ = require('lodash');
const RateLimiterMemory = require('rate-limiter-flexible').RateLimiterMemory;

const { SERVER } = require('./config');

const app = new Koa();

app.use(bodyParser({
    formLimit: '1GB'
}));

app.use(async (ctx, next) => {
    // ctx.state.ip = ctx.headers['x-real-ip'] || ctx.ip;
    ctx.state.ip = ctx.ip;
    ctx.assert(ctx.state.ip, 500, 'Unknow Error');
    await next();
});

const api = new Router();

api.use(require('./services/logger')((ctx, str, args) => {
    let suffix = '';
    if (_.isObject(ctx.body) && _.has(ctx.body, 'success') && !ctx.body.success) {
        suffix = ' ' + JSON.stringify(ctx.body);
    };
    console.log(`[${ctx.state.ip}] ${str}${suffix}`);
}));
// rate limit
const rateLimiter = new RateLimiterMemory({
    points: 50,
    duration: 1, // Per second
    blockDuration: 60 // 超出限制之后禁用时间（秒）
});
api.use(async (ctx, next) => {
    const ip = ctx.state.ip;
    try {
        await rateLimiter.consume(ip);
        await next();
    } catch (e) {
        console.log(`rate limit for ${ip}`);
        ctx.status = 403;
        const messages = [];
        messages.push(`Server received over 50 requests during 1 second from your ip ${ip}, please retry after 1 minute.`);
        messages.push(`我们的服务器在1秒内收到了来自你的IP(${ip})的超过50个请求，请降低请求频率，并在1分钟后重新访问本网站。`);
        ctx.body = messages.join('\n');
    }
});
// error handle
api.use(async (ctx, next) => {
    try {
        ctx.set({
            'Cache-Control': 'nocache',
            Pragma: 'no-cache',
            Expires: -1
        });
        await next();
    } catch (e) {
        console.error(e);
        ctx.body = {
            success: false,
            message: e.message
        };
    }
});

api.use('', require('./controllers/index').routes());
api.use('', require('./controllers/admin').routes());

app.use(mount('/api', api.routes()));
app.use(require('koa-static')(path.resolve(__dirname, '..', 'dist'), {
    maxage: SERVER.MAXAGE
}));
app.use(async (ctx) => {
    ctx.type = 'html';
    ctx.body = require('fs').createReadStream(path.resolve(__dirname, '..', 'dist', 'index.html'));
});

app.listen(SERVER.PORT, SERVER.ADDRESS);

console.log(`listen on http://${SERVER.ADDRESS}:${SERVER.PORT}`);
