
function ProxySourceAnalyzer(){
	//$ = require("jquery");
	var sysutil = require("util");
	var utils = require("./passport_utils.js");
	cheerio = require("cheerio");
	var fs = require("fs");
	var urlutil = require("url");
	var crypto = require("crypto");
	var http = require("http");
	var https = require("https");
	var dbFileName = "./passports.db";
	var dbStableFileName = "./passports_stable.db"
	var dbBkFileName = "./passports.db.bk";
	var passports = {};
	passports.ordered = [];
	passports.totalCount = 0;
	var PROXY_TEST_INTERVAL = 1000 * 3600;
	var PROXY_TEST_GROUP_COUNT = 5;
	var PROXY_RESPONSE_TIMEOUT = 10000;
	var TEST_URL_INSIDE = "www.baidu.com/cache/aladdin/ui/scrollbarv/scrollbarv.js";
	var TEST_INSIDE_SEGMENT = "opui";
	var TEST_URL_OUTSIDE = "ssl.gstatic.com/gb/js/sem_32d9c4210965b8e7bfa34fa376864ce8.js";
	var TEST_OUTSIDE_SEGMENT = "www.google.com";
	var analyzers = [];
	//$.support.cors = true;

	function toTimeString(time) {    
	    return time.getFullYear() + "-" + (time.getMonth() + 1 < 10 ? "0" : "") + (time.getMonth() + 1) + "-" + (time.getDate() < 10 ? "0" : "") + time.getDate() + " " + (time.getHours() < 10 ? "0" : "") + time.getHours() + ":" + (time.getMinutes() < 10 ? "0" : "") + time.getMinutes() + ":" + (time.getSeconds() < 10 ? "0" : "") + time.getSeconds();
	}
	function toDateString(time) {    
	    return time.getFullYear() + "-" + (time.getMonth() + 1 < 10 ? "0" : "") + (time.getMonth() + 1) + "-" + (time.getDate() < 10 ? "0" : "") + time.getDate() ;
	}

	function log(str, level)
	{
		var date = new Date();
		str = "[" + toTimeString(date) + "] " + str;
		switch(level)
		{
			case log.ERROR:
				str = "[ERROR] " + str;
				break;
			case log.WARN:
				str = "[WARN] " + str;
				break;
			case log.INFO:
				str = "[INFO] " + str;
				break;
			case log.TRACE:
				str = "[TRACE] " + str;
				break;
			default:
				str = "[INFO] " + str;
				break;
		}
		console.log(str);
	}
	log.ERROR = 1;
	log.WARN = 2;
	log.INFO = 3;
	log.TRACE = 4;

	function addConnect(proxy, type, speed)
	{
		proxy.connects = proxy.connects || {};
		proxy.connects[type] = proxy.connects[type] || {};
		proxy.connects[type].speed = speed;
		if (isNaN(speed)) {
			proxy.connects[type].pass = 0;
		}
		else
		{
			proxy.connects[type].pass = 1;
		}
	}
	ProxyItem = {};
	ProxyItem.TYPE = {};
	ProxyItem.TYPE.HOME = 0;
	ProxyItem.TYPE.ABROAD = 1;
	ProxyItem.PROTOCOL = {};
	ProxyItem.PROTOCOL.HTTP = 0;
	ProxyItem.PROTOCOL.HTTPS = 1;
	ProxyItem.PROTOCOL.BOTH = 2;
	function init()
	{
		log("starting proxy updating service...", log.INFO);
		passports.proxyList = {};
		setupAnalyzers();
		if(fs.existsSync(dbFileName))
		{	
			log("reading proxy database ...", log.INFO);
			var db = "";
			if(fs.existsSync(dbFileName))
			{
				db = fs.readFileSync(dbFileName, {flag: 'r+'}).toString();
			}		
			else
			{
				fs.readFileSync(dbFileName, {flag: 'w+'});
			}
			var lines = db.split("\n");			
			for(var i = 0; i < lines.length; i ++)
			{			
				var homespeed, abroadspeed, timestamp;
				var proxyItem = {};
				var items = lines[i].split("\t");
				proxyItem.ip = items[0];
				proxyItem.port = parseInt(items[1]);
				homespeed = parseFloat(items[2]);
				abroadspeed = parseFloat(items[3]);
				timestamp = parseInt(items[4]);
				addConnect(proxyItem, ProxyItem.TYPE.HOME, homespeed);
				addConnect(proxyItem, ProxyItem.TYPE.ABROAD, abroadspeed);
				proxyItem.timestamp = parseInt(items[4]);
				if(isNaN(proxyItem.port) || (isNaN(homespeed) && isNaN(abroadspeed)) || isNaN(proxyItem.timestamp))
				{
					continue;
				}	
				passports.proxyList[proxyItem.ip + ":" + proxyItem.port] = proxyItem;
			}
			log(lines.length + " lines loaded from database...", log.INFO);	
			orderProxyList();
		}
		if(fs.existsSync(dbStableFileName))
		{
			db = fs.readFileSync(dbStableFileName, {flag: 'r+'}).toString();
			var lines = db.split("\n");			
			for(var i = 0; i < lines.length; i ++)
			{
				var homespeed, abroadspeed, timestamp;
				var proxyItem = {};
				var items = lines[i].split("\t");
				var ip = items[0];
				var port = parseInt(items[1]);
				var connects = {};
				connects[ProxyItem.TYPE.HOME] = {};
				connects[ProxyItem.TYPE.ABROAD] = {};
				addToProxyList(ip, port, "http", connects);	
				log("add stable proxy " + ip + ":" + port + "", log.INFO);				
			}
			log(lines.length + " lines loaded from stable database...", log.INFO);	
		}
	}

	function startAnalyzers()
	{
		passports.totalCount = 0;
		passports.analyzing = true;

		var finishCount = 0;
		var endCallback = function (count)
		{
			finishCount ++;
			if(finishCount == analyzers.length && !passports.testing)
			{
				passports.analyzing = false;
				startProxyTesting();
			}
		}
		for(var i = 0; i < analyzers.length; i ++)
		{
			try{
				commonAnalyzer(analyzers[i], endCallback);
			}
			catch(e)
			{
				log("start analyzer failed, error=" + e.message);
			}			
		}
		return;
	}

	function loop()
	{
		setInterval(dumpProxyList, 60000);
		setInterval(startAnalyzers, 1800000);
		setInterval(startProxyTesting, 3600000);//3600000
		startAnalyzers();
	}

	function run()
	{
		init();
		loop();
	}

	function orderProxyList(connect, protocol)
	{
		passports.ordered = [];
		for(var i in passports.proxyList)
		{
			if(passports.proxyList[i].pass)
			{
				passports.ordered.push(passports.proxyList[i]);			
				passports.count ++;
			}
		}
		passports.ordered.sort(function(a, b){
			var value1 = a.innerspeed;
			var value2 = b.innerspeed;
			if(value1 > value2)
				return -1;
			else if(value1 == value2)
				return 0;
			else
				return 1;
		});	
	}

	function dumpProxyList()
	{
		var count = 0;
		var db = "";
		orderProxyList();
		for(var i = 0; i < passports.ordered.length; i ++)
		{
			db += passports.ordered[i].ip + "\t" + passports.ordered[i].port + "\t" + passports.ordered[i].connects[ProxyItem.TYPE.HOME].speed.toFixed(4) + "\t" + passports.ordered[i].connects[ProxyItem.TYPE.HOME].speed.toFixed(4) + "\t" + passports.ordered[i].timestamp + "\n";		
		}
		fs.writeFileSync(dbBkFileName, db);
		fs.renameSync(dbBkFileName, dbFileName);
		return;
	}

	function removeFromProxyList(ip, port)
	{
		var key = ip + ":" + port;
		delete passports.proxyList[key];
	}

	function altProxyProtocol(ip, port, protocol, alt)
	{
		var key = ip + ":" + port;
		if(ip && !isNaN(parseInt(port)) && passports.proxyList[key] == undefined)
		{
			var item = passports.proxyList[key];
			if (alt == "add") {
				if (!item.type) {
					item.type = protocol;
				}
				else if(item.type != protocol)
				{
					item.type = ProxyItem.PROTOCOL.BOTH;
				}
			}
			else if(alt == "del")
			{
				if (item.type == ProxyItem.PROTOCOL.BOTH) {
					item.type = protocol;
				}
				else if(item.type == protocol)
				{
					item.type = undefined;
				}
			}
		}

	}
	function addToProxyList(ip, port, type, connects)
	{
		connects = connects || {};
		var key = ip + ":" + port;
		if(ip && !isNaN(parseInt(port)) && passports.proxyList[key] == undefined)
		{
			passports.proxyList[key] = passports.proxyList[key] || {};
			passports.proxyList[key].ip = ip;
			passports.proxyList[key].port = port;
			if(passports.proxyList[key].type == undefined)
			{
				passports.proxyList[key].type = type;
			}
			else if(passports.proxyList[key].type != type)
			{
				passports.proxyList[key].type = ProxyItem.PROTOCOL.BOTH;
			}
			for(var i in connects)
			{
				addConnect(passports.proxyList[key],i, connects[i]);
			}
			
			var i;
			passports.proxyCount = 0;
			for (i in passports.proxyList) {
			    if (passports.proxyList.hasOwnProperty(i)) {
			        passports.proxyCount ++;
			    }
			}
			return true;
		}
		return false;
	}

	/*
		options
		{
			name: name
			urlPattern:["http://xxx/{page}"],
			pageRange:[0,100],
			listSelector: string or function returns jquery list
			rowParser: [ipselector, portselector, protoselector] or function returns [ip, port, proto]
			protocolParser: function or undefined
		}
	*/
	function setupAnalyzers(options)
	{
		//kuaidaili
		var optionsKuaidaili = {};
		optionsKuaidaili.name = "kuaidaili";
		optionsKuaidaili.urlPattern = ["http://www.kuaidaili.com/free/inha/{page}/", "http://www.kuaidaili.com/free/intr/{page}/", "http://www.kuaidaili.com/free/outha/{page}/", "http://www.kuaidaili.com/free/outtr/{page}/"];
		optionsKuaidaili.pageRange = [1, 20];
		optionsKuaidaili.listSelector = "tbody > tr";
		optionsKuaidaili.rowParser = function(row){return [row.find("td").eq(0).text(),row.find("td").eq(1).text(),row.find("td").eq(3).text()];};
		analyzers.push(optionsKuaidaili);

		//haodaili
		var optionsHaodaili = {};
		optionsHaodaili.name = "haodaili";
		optionsHaodaili.urlPattern = ["http://www.haodailiip.com/guonei/{page}", "http://www.haodailiip.com/guoji/{page}"];
		optionsHaodaili.pageRange = [1, 20];
		optionsHaodaili.listSelector = "table.proxy_table > tr";
		optionsHaodaili.rowParser = function(row){return [row.find("td").eq(0).text(),row.find("td").eq(1).text(),row.find("td").eq(3).text()];};
		optionsHaodaili.delay = 1500;
		analyzers.push(optionsHaodaili);		

		//ipcn
		var optionsIpcn = {};
		optionsIpcn.name = "ipcn";
		optionsIpcn.urlPattern = ["http://proxy.ipcn.org/proxylist.html", "http://proxy.ipcn.org/proxylist2.html"];
		optionsIpcn.pageRange = [0 ,0];
		optionsIpcn.pageParser = function($)
		{
			var list = []; 
			var ips = $("pre").text().match(/\d+\.\d+\.\d+\.\d+\:\d+/g);
			for (var i = 0; i < ips.length; i++) {
				var ipport = ips[i].split(":");
				if (ipport.length == 2) {
					list.push([ipport[0].trim(), ipport[1].trim(), "http"]);
				};				
			};
			return list;
		}
		analyzers.push(optionsIpcn);

		//ip400
		var optionsIp400 = {};
		optionsIp400.name = "ip400";
		optionsIp400.urlPattern = ["http://ip004.com/proxycate_{page}.html"];
		optionsIp400.pageRange = [0 ,0];
		optionsIp400.listSelector = "table#proxytable > tr";
		optionsIp400.rowParser = function(row){return [row.find("td").eq(0).text(),row.find("td").eq(1).text(),"http"];};
		analyzers.push(optionsIp400);

		//fldd
		var optionsFldd = {};
		optionsFldd.name = "fldd";
		optionsFldd.urlPattern = ["http://www.fldd.cn/index.asp?page={page}"];
		optionsFldd.pageRange = [1 ,25];
		optionsFldd.listSelector = "tbody > tr";
		optionsFldd.delay = 1500;
		optionsFldd.rowParser = function(row){return [row.find("td").eq(0).text(),row.find("td").eq(1).text(),row.find("td").eq(3).text()];};
		analyzers.push(optionsFldd);
		
		var optionsHttpdaili = {};
		optionsHttpdaili.name = "httpdaili";
		optionsHttpdaili.urlPattern = ["http://www.httpdaili.com/mfdl/"];
		optionsHttpdaili.pageRange = [0 ,0];
		optionsHttpdaili.listSelector = "tr";
		optionsHttpdaili.delay = 1500;
		optionsHttpdaili.rowParser = function(row){return [row.find("td").eq(0).text(),row.find("td").eq(1).text(),"http"];};
		analyzers.push(optionsHttpdaili);

		//66ip
		var options66ip = {};
		options66ip.name = "66ip";
		options66ip.urlPattern = ["http://www.66ip.cn/{page}.html"];
		options66ip.pageRange = [1 ,20];
		options66ip.listSelector = "tr";
		options66ip.rowParser = function(row){return [row.find("td").eq(0).text(),row.find("td").eq(1).text(),"http"];};
		analyzers.push(options66ip);

		//swei360
		var optionsSwei360 = {};
		optionsSwei360.name = "swei360";
		optionsSwei360.urlPattern = ["http://www.swei360.com/?page={page}"];
		optionsSwei360.pageRange = [1 ,10];
		optionsSwei360.listSelector = "tr";
		optionsSwei360.rowParser = function(row){return [row.find("td").eq(0).text(),row.find("td").eq(1).text(),row.find("td").eq(3).text()];};
		analyzers.push(optionsSwei360);

		var optionsGoubanjia = {};
		optionsGoubanjia.name = "goubanjia";
		optionsGoubanjia.urlPattern = ["http://proxy.goubanjia.com/free/gngn/index.shtml", "http://proxy.goubanjia.com/free/gnpt/index.shtml", "http://proxy.goubanjia.com/free/gwgn/index.shtml", "http://proxy.goubanjia.com/free/gwpt/index.shtml"];
		optionsGoubanjia.pageRange = [0 ,0];
		optionsGoubanjia.listSelector = "tbody > tr";
		optionsGoubanjia.rowParser = function(row){return [row.find("td").eq(0).children().not("*[style*='none']").text(),row.find("td").eq(1).text(),row.find("td").eq(3).text()];};
		analyzers.push(optionsGoubanjia);

		var optionsFreeProxyList = {};
		optionsFreeProxyList.name = "FreeProxyList";
		optionsFreeProxyList.urlPattern = ["http://www.sslproxies.org/", "http://free-proxy-list.net/uk-proxy.html", "http://free-proxy-list.net/anonymous-proxy.html"];
		optionsFreeProxyList.pageRange = [0 ,0];
		optionsFreeProxyList.listSelector = "tbody > tr";
		optionsFreeProxyList.rowParser = function(row){return [row.find("td").eq(0).text(),row.find("td").eq(1).text(),"http"];};
		analyzers.push(optionsFreeProxyList);


		function str_rot13(str) {
			return (str + '')
			    .replace(/[a-z]/gi, function(s) {
		      		return String.fromCharCode(s.charCodeAt(0) + (s.toLowerCase() < 'n' ? 13 : -13));
		    	});
		}
		var optionsCoolProxy = {};
		optionsCoolProxy.name = "CoolProxy";
		optionsCoolProxy.urlPattern = ["http://www.cool-proxy.net/proxies/http_proxy_list/sort:score/direction:desc/page:{page}"];
		optionsCoolProxy.pageRange = [1 ,10];
		optionsCoolProxy.listSelector = "tr";
		optionsCoolProxy.rowParser = 
		function(row){
			var ip = row.find("td > script").eq(0).text();
			if(!ip)
			{
				return null;
			}
			ip = ip.match(/\"(.+)\"/);	
			if(!ip)
			{
				return null;
			}				
			if (ip) {
				ip = ip[1];	
			}
			else
			{
				return null;
			}
			ip = new Buffer(str_rot13(ip), 'base64').toString();
			return [ip,row.find("td").eq(1).text(),"http"];
		};
		analyzers.push(optionsCoolProxy);

		var optionsMrhinkydink = {};
		optionsMrhinkydink.name = "Mrhinkydink";
		optionsMrhinkydink.urlPattern = ["http://www.mrhinkydink.com/proxies{page}.htm"];
		optionsMrhinkydink.pageRange = [1 ,14];
		optionsMrhinkydink.listSelector = "tr";
		optionsMrhinkydink.firstPageNoNum = 1;
		optionsMrhinkydink.rowParser = function(row){return [row.find("td").eq(0).text().replace('*',''),row.find("td").eq(1).text(),"http"];};
		analyzers.push(optionsMrhinkydink);



		
	}

	function commonAnalyzer(options, endCallback)
	{
		log("analyze " + options.name + "...", log.INFO);
		var count = 0;
		var finishIdx = 0;
		var pageCount = options.pageRange[1] - options.pageRange[0];
		var processes = [];
		options.delay = options.delay || 1;
		function analyzer(html, url)
		{
			if(html)
			{
				//console.log(html);
				var $ = cheerio.load(html);
				var curCount = 0;
				if(options.pageParser)
				{
					var rst = options.pageParser($);
					for (var i = 0; i < rst.length; i++) {
						var row = rst[i];
						var connects = {};
						connects[ProxyItem.TYPE.HOME] = {};
						connects[ProxyItem.TYPE.ABROAD] = {};	
						if(addToProxyList(row[0].trim(), row[1].trim(), row[2].trim().toLowerCase(), connects))
						{
							count ++;	
							curCount ++;
						}
					};
				}
				else
				{					
					var list;
					if (typeof(options.listSelector) == typeof("")) {
						list = $(options.listSelector);
					}
					else
					{
						list = options.listSelector($);
					}
					for (var i = 0; i < list.length; i++) {
						var row = [];
						if (sysutil.isArray(options.rowParser)) {
							var ip = list.eq(i).find(options.rowParser[0]).text();
							var port = list.eq(i).find(options.rowParser[1]).text();
							var protocol = list.eq(i).find(options.rowParser[2]).text();
							if (options.protocolParser) {
								protocol = protocolParser(protocol);
							};

							row = [ip, port, protocol];
						}
						else
						{
							row = options.rowParser(list.eq(i));
							if(!row)
								continue;
						}

						if (row[2].trim().toLowerCase().indexOf("http") == -1) {
							continue;
						};					
						var connects = {};
						connects[ProxyItem.TYPE.HOME] = {};
						connects[ProxyItem.TYPE.ABROAD] = {};
						
						if(addToProxyList(row[0].trim(), row[1].trim(), row[2].trim().toLowerCase(), connects))
						{
							//log(options.name + " add " + row[2].trim() + "://" + row[0].trim() + ":" + row[1].trim(), log.INFO);
							count ++;	
							curCount ++;
						}
					};
				}
				log(url + " count=" + curCount, log.INFO);
			}			
		}

		var finish_process = 0;
		for (var j = 0; j < options.urlPattern.length; j++) {
			processes.push(options.pageRange[0]);
			var scrapeCallback;
			scrapeCallback  = 
			function(result){
				try
				{
					analyzer(result.data, result.url);
				}				
				catch(e)
				{
					log("analyze " + result.url + "failed, error=" + e.message, log.ERROR);
				}
				var patternIndex = arguments.callee.index;

				setTimeout(
					function(){
						processes[patternIndex] ++;					
						var page = processes[patternIndex];		
						var url = options.urlPattern[patternIndex].replace(/\{page\}/, page);					
						try
						{

							if (page <= options.pageRange[1]) {								
								//log(url, log.INFO);
								utils.scrapePage(url, scrapeCallback);
							}
							else
							{
								finish_process ++;
								if (finish_process == options.urlPattern.length) {
									log("analyze " + options.name + " done, total " + count, log.INFO);
									passports.totalCount += count;
									if(endCallback)
										endCallback(count);	
								};
							}
						}
						catch(e)
						{
							log("scrape " + url + " failed, error=" + e.stack, log.ERROR);
						}
				}, options.delay);
			}
			scrapeCallback.index = j;
			var url;
			if(options.firstPageNoNum)
				url = options.urlPattern[j].replace(/\{page\}/, "");
			else
				url = options.urlPattern[j].replace(/\{page\}/, processes[processes.length - 1]);
			utils.scrapePage(url, scrapeCallback);
		}			
	}

	function xiciAnalyzer(endCallback){
		log("analyze xici...", log.INFO); 
		var count = 0;
		var maxCount = 1;
		var finishIdx = 0;
		function analyzer(html)
		{
			if(html)
			{
				var $ = cheerio.load(html);
				var list = $("table#ip_list").find("tr");
				for(var j = 0; j < list.length; j ++)
				{
					var tds = $(list[j]).find("td");
					if(tds.length == 0)
						continue;
					var ip = $(tds[2]).text();
					var port = $(tds[3]).text();
					var type = $(tds[6]).text();
					if(type.indexOf("HTTP") == -1)
					{
						//console.log("type " + type);
						continue;
					}				
					type = type.toLowerCase();
					log("xici add " + type + "://" + ip + ":" + port, log.INFO);
					var connects = {};
					connects[ProxyItem.TYPE.HOME] = {};
					connects[ProxyItem.TYPE.ABROAD] = {};
					
					if(addToProxyList(ip, port, type, connects))
						count ++;			
				}
			}

			if(++finishIdx == maxCount * 3)
			{
				log("analyze xici done, total " + count, log.INFO);
				passports.totalCount += count;
				if(endCallback)
					endCallback(count);	
			}
		}
		for(var i = 1; i <= maxCount; i ++)
		{
			//$.get("http://www.xicidaili.com/nt/" + i, analyzer).error(function(e){analyzer();console.log(e.responseText)});
			utils.request("http://www.xicidaili.com/nn/" + i, function(result){analyzer(result.data);});
			
			//cheerio.get("http://www.xicidaili.com/wn/" + i, analyzer).error(function(e){analyzer();console.log(e.responseText)});
		}	
	}

	function testSingleProxy(list, idx, connect, url, testSegment, endCallback)
	{
		var i = list[idx];
		var proxyItem = passports.proxyList[i];
		var start = new Date();
		var urlObj = urlutil.parse(url);
		var header = {};
		if (urlObj && urlObj.host) {
			header["host"] = urlObj.host;
		};

		proxyItem.test[url] = {};
		var option = {
			host: proxyItem.ip,
			port: proxyItem.port,
			path: url,
			headers: header
		};


		if(start - proxyItem.timestamp < PROXY_TEST_INTERVAL)
		{
			proxyItem.test[url].pass = 1;
			endCallback(list, idx, 1, "", connect, protocol, url); //skip			
			return;
		}

		//log("test " + urlObj.protocol + "//" + proxyItem.ip + ":" + proxyItem.port + " segment=" + testSegment + "...", log.INFO);
		var request, protocol;
		if(urlObj.protocol == "http:")
		{
			request = http;
			protocol = ProxyItem.PROTOCOL.HTTP;
		}
		else if (urlObj.protocol == "https:")
		{
			request = https;
			protocol = ProxyItem.PROTOCOL.HTTPS;
		}
		else
			return;

		request.get(option, function(res){
			var delay = new Date().getTime() - start.getTime();
			var length = 0;
			res.on('data', function(chunk){
				//console.log(chunk.toString());
				if(chunk.toString().indexOf(testSegment) != -1)
				{
					proxyItem.test[url].pass = 1;	

				}
				//console.log(chunk.toString().indexOf(testSegment));
				//console.log(chunk.toString());
				length += chunk.length;
			});
			res.on('end', function(){
				var msg = "";
				var pass = 0;
				//console.log(proxyItem.connects[connect].pass + " " + connect);	
				proxyItem.test[url].t = 1;			
				if(proxyItem.test[url].pass)
				{
					var end = new Date().getTime();
					var cost = end - start.getTime();
					proxyItem.timestamp = end;
					proxyItem.connects[connect].oldSpeed = proxyItem.connects[connect].speed;
					proxyItem.connects[connect].speed = (length / 1024 / cost * 1000);
					pass = 1;
				}
				else
				{
					var end = new Date().getTime();
					var cost = end - start.getTime();
					proxyItem.connects[connect].oldSpeed = proxyItem.connects[connect].speed;
					proxyItem.connects[connect].speed = 0;
					proxyItem.connects[connect].pass = 0;
					proxyItem.timestamp = end;
					msg = "status code:" + res.statusCode;
					pass = 0;
				}
				endCallback(list, idx, pass,  msg, connect, protocol, url);

		});
		}).on("error", function(e){
			var cost = new Date().getTime() - start.getTime();
			if(proxyItem.test[url].t != undefined)
				console.log("!!!err " + e.message + " t=" + proxyItem.connects[connect].t);
			proxyItem.test[url].pass = 0;			
			endCallback(list, idx, 0, e.message, connect, protocol, url);
		}).setTimeout(PROXY_RESPONSE_TIMEOUT, function(e){			
			this.abort();
		});
	}

	function startProxyTesting()
	{	
		if(passports.testing)
			return;
		var succ = 0;
		var fail = 0;
		var total = 0;
		var groupIndex = 0;	
		var testGroups = new Array(PROXY_TEST_GROUP_COUNT);
		for(var i in passports.proxyList)
		{
			testGroups[groupIndex % PROXY_TEST_GROUP_COUNT] = testGroups[groupIndex % PROXY_TEST_GROUP_COUNT] || [];
			testGroups[groupIndex % PROXY_TEST_GROUP_COUNT].push(i);
			groupIndex ++;
		}

		log("startProxyTesting, total=" + passports.proxyCount, log.INFO);
		function endCallback(list, idx, pass, msg, type, protocol, url)
		{
			var key = passports.proxyList[list[idx]].ip + ":" + passports.proxyList[list[idx]].port;
			var proxyItem = passports.proxyList[list[idx]];
			var protocolName;
			switch(protocol)
			{
				case ProxyItem.PROTOCOL.HTTP:
					protocolName = "http";
					break;
				case ProxyItem.PROTOCOL.HTTPS:
					protocolName = "https";
					break;				
			}
			if(pass == 1){
				succ ++;			
				altProxyProtocol(proxyItem.ip, proxyItem.port, protocol, "add");
				proxyItem.connects[type].oldSpeed = proxyItem.connects[type].oldSpeed || 0;

				log("proxy " + key + " avaiable to " + (type == 0 ? "NATIONWIDE" : "WORLDWIDE") + " via " + protocolName + " , speed " + proxyItem.connects[type].speed.toFixed(4) + "KB/s (" + (proxyItem.connects[type].oldSpeed < proxyItem.connects[type].speed ? "-" : "+") + ")");
			}
			else if(pass == 0)
			{
				fail ++;
				//log(key + " failed " + msg + ", pass " + succ + ", fail " + fail);				
				proxyItem.connects[type].oldSpeed = proxyItem.connects[type].oldSpeed || 0;
				altProxyProtocol(proxyItem.ip, proxyItem.port, protocol, "del");
				if(proxyItem.connects[type].oldSpeed > 0)
				{
					log("proxy " + key + " to " +(type == 0 ? "NATIONWIDE" : "WORLDWIDE")+ " via " + protocolName + " no longer avaiable");
				}				
				removeFromProxyList();
			}

			if(passports.pauseTesting)
			{
				passports.testing = false;
				setTimeout(
					function()
					{
						endCallback(list, idx, pass, msg, type, protocol, url);
					}, 5000);
			}
			else
			{
				passports.testing = true;
				proxyItem.test[url].pass = 2
				for(i in proxyItem.test)
				{
					//console.log(i + " " + proxyItem.connects[i].pass);
					if(proxyItem.test[i].pass != 2)
					{
						//log(proxyItem.ip + ":" + proxyItem.port + " waiting connect " + i, log.INFO);
						return;
					}
				}


				//log(proxyItem.ip + ":" + proxyItem.port + " test done ", log.INFO);				
				total ++;
				if(++idx < list.length)
				{			
						setTimeout(
							function()
							{
								var nextProxy = passports.proxyList[list[idx]];
								nextProxy.test = {};
								nextProxy.type = undefined;
								//log("idx=" + idx + ", list=" + list.length + ", ip=" + list[idx], log.INFO);
								testSingleProxy(list, idx, ProxyItem.TYPE.HOME, "http://" + TEST_URL_INSIDE, TEST_INSIDE_SEGMENT, endCallback);
								testSingleProxy(list, idx, ProxyItem.TYPE.ABROAD, "http://" + TEST_URL_OUTSIDE, TEST_OUTSIDE_SEGMENT, endCallback);
								testSingleProxy(list, idx, ProxyItem.TYPE.HOME, "https://" + TEST_URL_INSIDE, TEST_INSIDE_SEGMENT, endCallback);
								testSingleProxy(list, idx, ProxyItem.TYPE.ABROAD, "https://" + TEST_URL_OUTSIDE, TEST_OUTSIDE_SEGMENT, endCallback);								
							}, 
						1);
				}
				else if(total >= passports.proxyCount)
				{
					log("all done, " + succ + " pass, " + fail + " failed");
					passports.testing = false;
				}
			}
		}

		for(var i = 0; i < PROXY_TEST_GROUP_COUNT; i ++)
		{
			if(testGroups[i] == undefined)
				continue;
			var nextProxy = passports.proxyList[testGroups[i][0]];
			nextProxy.test = {};
			nextProxy.type = undefined;
			testSingleProxy(testGroups[i], 0, ProxyItem.TYPE.HOME, "http://" + TEST_URL_INSIDE, TEST_INSIDE_SEGMENT, endCallback);
			testSingleProxy(testGroups[i], 0, ProxyItem.TYPE.ABROAD, "http://" + TEST_URL_OUTSIDE, TEST_OUTSIDE_SEGMENT, endCallback);
			testSingleProxy(testGroups[i], 0, ProxyItem.TYPE.HOME, "https://" + TEST_URL_INSIDE, TEST_INSIDE_SEGMENT, endCallback);
			testSingleProxy(testGroups[i], 0, ProxyItem.TYPE.ABROAD, "https://" + TEST_URL_OUTSIDE, TEST_OUTSIDE_SEGMENT, endCallback);			
		}	
		passports.testing = true;
	}
	//public functions
	this.getProxyList = function()
	{
		return passports.ordered;
	}

	this.getTotalProxyCount = function()
	{
		return passports.totalCount;
	}

	this.activate = function(ip, port, length ,cost, timestamp)
	{
		var key = ip + ":" + port;
		var proxyItem = passports.proxyList[key];
		if(proxyItem)
		{
			proxyItem.timestamp = timestamp;
		}
		else
		{
			console.log(key);
		}
	}

	this.isTesting = function()
	{
		return passports.testing;
	}

	this.isAnalyzing = function()
	{
		return passports.analyzing;
	}

	this.pauseTesting = function(pause)
	{
		passports.pauseTesting = pause;
	}
	
	this.start = run;
}
module.exports = new ProxySourceAnalyzer();