const readline = require('readline');
const { Masscan } = require('node-masscan');
const { QuickDB } = require("quick.db");
const { getStatus } = require("mc-server-status");
const { Webhook } = require('dis-logs')
const fs = require("fs");
const cfg = require('./config/config.json')

const scan_db = new QuickDB();

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

const log = new Webhook(cfg.scanning_alerts.webhook);

let masscan = new Masscan();

/**
 * * onServerFound(data)
 * @param {data} object with the required information to process all the data
 */
async function onServerFound(data) {
    let servers_db = await scan_db.get(`servers`).catch(e => { throw e }); // https://quickdb.js.org/overview/docs#has
    let server_exists = servers_db ? servers_db.map(a => a.ip == data.ip ? true : false) : false;

    /**
     * * Server DB
     * @param servers_db will have an array from the database with all the servers
     * ! Improove code
     */
    if (server_exists) return log.console("Already seen server: " + data.ip + ", skipping!");
    let discovered = new Date()
    data.discovered = discovered;
    data.lastTimeOnline = Date.now();
    let online = (data.players || {}).online;
    await scan_db.push("servers", {
        ip: data.ip,
        description: typeof data.description == "string" ? data.description : JSON.stringify(data.description),
        version: (data.version ? data.version : {}).name || null,
        protocol: (data.version ? data.version : {}).protocol || null,
        favicon: data.favicon || null,
        modded: data.modded,
        allow_crack: null,
        whitelist: null,
        players: players.map(p => p),
        max_players: (data.players ? data.players : {}).max || null,
        online: online !== undefined ? online : null,
        discovered: discovered,
        lastTimeOnline: new Date()
    }).catch(e => { throw e });

    if (cfg.scanning_alerts.key_strings) {
        cfg.scanning_alerts.key_strings.forEach(str => {
            if (JSON.stringify(data).includes(str))
                log.success(`Found the key string ${str} on a server request\nIP: ${data.ip}\nMOTD: ${JSON.stringify(data.description)}\nVersion: ${(data.version ? data.version : {}).name}`)
        })
    }
}


/**
 * * exportData()
 * Exports all the data inside quick.db database to a json file
 * @output scan_db_<hour>_<minute>.json
 */
async function exportData() {
    let exd = new Date()
    await scan_db.all().then(array => {
        if (array.length > 0)
            fs.writeFileSync(`./scan_db_${exd.getHours()}_${exd.getMinutes()}.json`, JSON.stringify(array));
    })
    log.success(`Exported all database to: ./scan_db_${exd.getHours()}_${exd.getMinutes()}.json`)
}

/**
 * * found
 * Triggers every time masscan recives a response
 * @param ip of the server
 * @param port is not used as we only scan in 1 port
 */
masscan.on('found', (ip, port) => {
    getStatus(ip, 25565, { timeout: 1500 }).then((response) => {
        response.ip = ip;
        // response.ping = undefined;
        // response.favicon = undefined;
        response.modded = false;
        if (response.forgeData || response.modinfo || response.modpackData) {
            response.forgeData = undefined;
            response.modinfo = undefined;
            response.modpackData = undefined;
            response.modded = true;
        }
        onServerFound(response).catch(e => { throw e });
    }).catch((reason) => { log.error(`mc-server-status exception: ${message}`); });
})


/**
 * * error
 * Triggers every time node-masscan gets an exception
 * @param message of the error
 */
masscan.on('error', (message) => {
    log.error(`node-masscan exception: ${message}`);
});

/**
 * * complete
 * Triggers only wen the scan has been finished
 */
masscan.on('complete', () => {
    log.success("Congrats, you scanned the entire internet!");
    exportData();
    exit(0);
})


rl.question(`Start scannig ip-range (${cfg.IPRange}), port-range (${cfg.portRange}), at rate of (${cfg.maxRate}p/s)? (Y/N) `, function (answer) {
    if (answer.toLocaleLowerCase() == "yes" || answer.toLocaleLowerCase() == "y") {
        log.console("Starting node-masscan...")
        masscan.start(cfg.IPRange, cfg.portRange, cfg.maxRate, cfg.excludeConf);
    }
    else {
        log.console("Cancelled.")
        rl.close();
    }
});


/*
{
  version: { protocol: 736, name: 'Velocity 1.7.2-1.19.2' },
  players: { online: 683, max: 1, sample: [ [Object], [Object] ] },
  description: { extra: [ [Object], [Object], [Object], [Object] ], text: '' },
  favicon: 'data:image/png;base64,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',
  ping: 119
}
*/