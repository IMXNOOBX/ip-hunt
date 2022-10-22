const readline = require('readline');
const { Masscan } = require('node-masscan');
const { QuickDB } = require("quick.db");
const status = require("mc-server-status");
const cfg = require('./config/config.json')

const db = new QuickDB();

const rl = readline.createInterface({
	input: process.stdin,
	output: process.stdout
});

let masscan = new Masscan();



async function onServerFound(data) {
    let server_exists = await database.serverExists(data.ip).catch(e => {throw e});
    // First checking players
    let players = (data.players ? data.players : {}).sample || [];
    players = players.filter(p => (p && p.id && p.id.length > 10 && p.name && !p.name.startsWith("§")));

    if (players.length > 0) {
        print("\t╘═► Players online: " + players.map(p => clc.yellowBright((p || {}).name)).join(", "));
    }
    players.forEach(async player => {
        let player_exists = await database.playerIdExists(player.id).catch(e => {throw e});
        if(!player_exists) {
            player.serversPlayed = [data.ip];
            database.setPlayer(player).catch(e => {throw e});
        } else {
            let player_data = await database.getPlayerData(player.id).catch(e => {throw e});
            let servers_played = player_data.serversPlayed;
            let server_index = servers_played.findIndex(s => s == data.ip);
            if(server_index == -1) {
                servers_played.push(data.ip);
                print(`\t${clc.magenta.underline("[RARE]")} ${clc.yellowBright(player.name)} is a fancy boy he plays on ${clc.redBright(servers_played.join(", "))}`);
            }
            database.setPlayer(player_data).catch(e => {throw e});
        }
    });
    
    // Then updating server data
    let discovered = new Date()
    if(server_exists) {
        print("\t╘═► Server already exists, updating lastTimeOnline");
        let oldData = await database.getServerByIp(data.ip).catch(e => {throw e});
        for (let player of players) {
            player.serversPlayed = undefined;
            if (!oldData.players.some(p => p === player.id)) {
                oldData.players.push(player.id);
                print(`\t╘═► ${clc.yellowBright(player.name)} is a new player on that server (${clc.blackBright(player.id)})`);
            }
        }
        discovered = oldData.discovered;
        players = oldData.players.filter(p => (p && p.length > 10)).map(p => {return {id: p}});
    } 
    data.discovered = discovered;
    data.lastTimeOnline = Date.now();
    let online = (data.players || {}).online;
    database.setServer({
        ip: data.ip,
        description: typeof data.description == "string" ? data.description : JSON.stringify(data.description),
        version: (data.version ? data.version : {}).name || null,
        protocol: (data.version ? data.version : {}).protocol || null,
        modded: data.modded,
        allow_crack: null,
        whitelist: null,
        players: players.map(p => p.id),
        max_players: (data.players ? data.players : {}).max || null,
        online: online !==undefined ? online : null,
        discovered: discovered,
        lastTimeOnline: new Date()
    }).catch(e => {throw e});
    
}


masscan.on('found', (ip, port) => {
	status.getStatus(ip, 25565, {timeout: 1500}).then((response) => {
        response.ip = ip;
        response.ping = undefined;
        response.favicon = undefined;
        response.modded = false;
        if (response.forgeData || response.modinfo || response.modpackData) {
            response.forgeData = undefined;
            response.modinfo = undefined;
            response.modpackData = undefined;
            response.modded = true;
        }
        console.log(`Found : ${clc.redBright(ip)} on port ${ports}   |   rate=${masscan.rate} percentage=${masscan.percentage}%`);
        onServerFound(response).catch(e => {throw e});
    }).catch((reason) => {});
})

masscan.on('error', (message) => {
    console.log(`Masscan error : ${message}`);
});

masscan.on('complete', () => {
    console.log(clc.greenBright("Congrats, you scanned the entire internet !"));
    exit(0);	
})

rl.question('Start Scannig? ', function (answer) {
	if (answer.toLocaleLowerCase() == "yes" || answer.toLocaleLowerCase() == "y")
		masscan.start(cfg.IPRange, cfg.portRange, cfg.maxRate, cfg.excludeConf);
	else
		console.log("Cancelled")
		rl.close();
});