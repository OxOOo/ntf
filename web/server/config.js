const path = require('path');
const fs = require('fs');
const _ = require('lodash');
const yaml = require('js-yaml');

const config = yaml.safeLoad(fs.readFileSync(path.join(__dirname, '..', 'config.yml'), 'utf-8'));

exports.SERVER = _.pick(config.SERVER, ['ADDRESS', 'PORT', 'SECRET_KEYS', 'MAXAGE']);

exports.ADMIN_PASSWORD = config.ADMIN_PASSWORD;

exports.MANAGE_SOCK_PATH = config.MANAGE_SOCK_PATH;
