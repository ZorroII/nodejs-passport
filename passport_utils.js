var http = require('http');
var https = require('https');
var urlparser = require('url');
var zlib = require('zlib');
var cheerio = require("cheerio");
var util = require("util");

HTTP_MAX_TIMEOUT = 120000;
HTTP_MAX_RETRY_COUNT = 2;
var utils = {};
utils.toTimeString = function(time) {    
    return time.getFullYear() + "-" + (time.getMonth() + 1 < 10 ? "0" : "") + (time.getMonth() + 1) + "-" + (time.getDate() < 10 ? "0" : "") + time.getDate() + " " + (time.getHours() < 10 ? "0" : "") + time.getHours() + ":" + (time.getMinutes() < 10 ? "0" : "") + time.getMinutes() + ":" + (time.getSeconds() < 10 ? "0" : "") + time.getSeconds();
}
utils.toDateString = function(time) {    
    return time.getFullYear() + "-" + (time.getMonth() + 1 < 10 ? "0" : "") + (time.getMonth() + 1) + "-" + (time.getDate() < 10 ? "0" : "") + time.getDate() ;
}

utils.get_days_ago_date = function (days, round) {
    var date = new Date(new Date().getTime() - days * 24 * 3600 * 1000);
    if(round)
    {
        date.setHours(0, 0, 0, 0);
    }
    return date;
}

utils.get_hours_ago_date = function (hours, round) {
    var date = new Date(new Date().getTime() - hours * 3600 * 1000);
    if(round)
    {
        date.setMinutes(0, 0, 0);
    }
    return date;
}
utils.to_date_string = utils.toDateString;
utils.to_time_string = utils.toTimeString;

utils.log = function(str, level)
{
	var date = new Date();
	str = "[" + utils.toTimeString(date) + "] " + str;
	switch(level)
	{
		case utils.ERROR:
			str = "[ERROR] " + str;
			break;
		case utils.WARN:
			str = "[WARN] " + str;
			break;
		case utils.INFO:
			str = "[INFO] " + str;
			break;
		case utils.TRACE:
			str = "[TRACE] " + str;
			break;
	}
	console.log(str);
}

utils.LOG_ERROR = 1;
utils.LOG_WARN = 2;
utils.LOG_INFO = 3;
utils.LOG_TRACE = 4;

/*
 *	并发异步请求处理器,并发执行批量异步函数，等待所有返回后，通过回调传出所有结果。
    calls: 函数数组,需要有相同的参数，并且最后一个参数为function(data){..}形式回调
    callback: 所有异步函数返回后统一回调函数, 在calls中所有函数返回后被调用,
    形式为function(data, param){},data为结果数组，结果为calls中各函数的回调函数返回的值，
    结果在data中的下标对应其相应的函数在calls数组中的下标相同, param为invoke时传入参数,无需请传入null
 */
utils.concurrent = function(calls, callback, insts)
{
    this.calls = calls;
    this.callback = callback;
    this.insts = insts || [];        
    var _this = this;
    /*do not pass callback*/
    this.invoke = function (args) {
        var arg_array = Array.prototype.slice.call(arguments);
        if(util.isArray(arg_array[0]))
        {
            arg_array = arg_array[0];
        }
        return this._internal_invoke({arg: arg_array, has_param: false});
    }
    
    this.invoke_with_param = function (args) {
        var arg_array = Array.prototype.slice.call(arguments);
        var param = arg_array.pop();
        if(util.isArray(arg_array[0]))
        {
            arg_array = arg_array[0];
        }                
        return this._internal_invoke({arg: arg_array, param: param, has_param: true});
    }
    
    this._internal_invoke = function(invoke_obj){
        var start_time = new Date().getTime();
        var return_data = [];
        var returned = 0;
        var has_param = invoke_obj.has_param;
        var param = invoke_obj.param;
        
        for(var i = 0; i < this.calls.length; i ++)
        {
            var arg_array = Array.prototype.slice.call(invoke_obj.arg);
            var my_callback = function(data){
                return_data[arguments.callee.i] = data;
                console.log("concurrent " + start_time + ": task " + arguments.callee.i + " returned, cost " + (new Date().getTime() - start_time) + "ms");
                if(++ returned == calls.length)
                {
                    returned = 0;                    
                    console.log("concurrent " + start_time + " done, cost " + (new Date().getTime() - start_time) + "ms");
                    _this.callback(return_data, param);
                }
            }
            my_callback.i = i;
            if(arg_array != undefined)
            {
                if('[object Array]' != Object.prototype.toString.call(arg_array[0]))
                {
                    arg_array.push(
                        my_callback
                    );
                    this.calls[i].apply(this.insts[i] || null, arg_array);            
                }
                else
                {
                    arg_array[i].push(
                        my_callback
                    );
                    this.calls[i].apply(this.insts[i] || null, arg_array[i]);                        
                }
            }
            else{
                    this.calls[i].apply(this.insts[i] || null, [my_callback]);
            }
        }
    }
}

utils.scrapePage = function(url, callback, options)
{
     utils.request(url, 
        function(resp)
        {
            var line;
            if(resp.status == 302)
            {
                var realurl = resp.headers["Location"];
                utils.request(realurl, callback, options);
                log("url " + url + " redirect to " + realurl);
                return;
            }
            else if(line = resp.data.match(/<meta\s+http-equiv="refresh".*>/i))
            {
                line = line[0];
                var realurl = line.match(/(http:\/\/[^" >]+)/);
                if (!realurl) {
                    realurl = line.match(/([^" >\.=]+\.[^" >]+)/);
                    if (realurl) {
                        realurl = realurl[1];
                    };
                };
                if (realurl) {
                    log("url " + url + " redirect to " + realurl);
                    utils.request(realurl, callback, options);
                    return;
                };
            }
            callback(resp);
        },
    options);
}

utils.request = function(url, callback, options)

{
    options = options || {};
    var method = options.method || "GET";
    var headers = options.headers || {};
    var proxyHost = options.proxyHost;
    var proxyPort = options.proxyPort;
    var timeout = options.timeout || HTTP_MAX_TIMEOUT;
    var urlObj = urlparser.parse(url);
    var result = {};    
    result.data = "";
    result.url = url;
    headers['User-Agent'] = headers['User-Agent'] || "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.33 (KHTML, like Gecko) Chrome/27.0.1430.0 Safari/537.33";
    headers['Accept'] = headers['Accept'] || "*/*";
    headers['Accept-Charset'] = headers['Accept-Charset'] || "GBK,utf-8;q=0.7,*;q=0.3";
    headers['Accept-Encoding'] = headers['Accept-Encoding'] || "gzip,deflate,sdch";
    headers['Accept-Language'] = headers['Accept-Language'] || "zh-CN,zh;q=0.8";
    headers['Connection'] = headers['Connection'] || "keep-alive";

    var option = {
        method: method,
        headers: headers,
        agent: headers['Connection'] == 'keep-alive' ? undefined : false,
        rejectUnauthorized: false
    };
    options.tried = options.tried == undefined ? 0 : options.tried + 1;
    if(proxyHost && proxyPort)
    {
        //use proxy
        option.path = url;
        option.host = proxyHost;
        option.port = proxyPort;
    }
    else
    {
        option.path = urlObj.path;
        option.hostname = urlObj.hostname;
        option.port = urlObj.port || 80;
    }    
    function onResponse(resp)
    {
        result.status = resp.statusCode;        
        if(resp.statusCode <= 400)
        {
            result.data = "";
            result.cookie = resp.headers['cookie'];
            result.headers = resp.headers;
            var pipe = undefined;
            if(resp.headers['content-encoding'] && resp.headers['content-encoding'].indexOf("gzip") != -1){
                pipe = resp.pipe(zlib.createGunzip());
            }
            else if(resp.headers['content-encoding'] && resp.headers['content-encoding'].indexOf("deflate") != -1)
            {
                pipe = resp.pipe(zlib.createInflate());
            }
            else
            {
                pipe = resp;
            }
            pipe.on('data',function(chunk){
                    result.data += chunk.toString('utf8');                   
                }).on('end', function(){
                    callback(result);
                });
        }
        else
        {
            if(options.tried < HTTP_MAX_RETRY_COUNT)
            {
                utils.log("request to " + url + " error, status = " + resp.statusCode + ", retry", utils.LOG_ERROR);
                setTimeout(function(){utils.request(url, callback, options)}, 1000);
            }
            else
            {                
                utils.log("request to " + url + " failed, abort, status = " + resp.statusCode, utils.LOG_ERROR);
                callback(result);
            }  
        }
    }
    var client;
    if(urlObj.protocol.indexOf('https') != -1)
    {
        client = https.request(option, onResponse);

    }
    else
    {
        client = http.request(option, onResponse);
    }
    client.on('error', function(e){
        if(options.tried < HTTP_MAX_RETRY_COUNT)
        {
            utils.log("request to " + url + " error, " + e.message + ", retry", utils.LOG_ERROR);
            setTimeout(function(){utils.request(url, callback, options)}, 1000);                
        }
        else
        {            
            utils.log("request to " + url + " error, " + e.message + ", abort", utils.LOG_ERROR);
            client.socket.destroy();
            callback(result);
        }        

    }).setTimeout(timeout, 
        function(){
            if(options.tried < HTTP_MAX_RETRY_COUNT)
            {
                utils.log("request to " + url + " timeout, retry ", utils.LOG_ERROR);
                setTimeout(function(){utils.request(url, callback, options)}, 1000);
            }
            else
            {
                result.status = 408;
                utils.log("request to " + url + " timeout, abort  " + result.status, utils.LOG_ERROR);
                client.socket.destroy();
            }
        }
    );
    client.end();
    return true;
}

utils.try_format_datetime = function(string){
    try{
        return utils.toTimeString(new Date(utils.try_parse_datetime(string)));
    }
    catch(e)
    {
        utils.log("format datetime failed: " + e.message);
        return false;
    }
}

utils.try_parse_datetime = function (string) {
    var formated = string.replace(/[年月\-]/g, "\/").replace("日", "").replace(/(今天)|(today)/, utils.to_date_string(new Date())).replace(/(昨天)|(yesterday)/, utils.to_date_string(utils.get_days_ago_date(1))).replace(/(前天)/, utils.to_date_string(utils.get_days_ago_date(2))).replace(/(明天)|(tomorrow)/, utils.to_date_string(utils.get_days_ago_date(-1))).replace(/(后天)/, utils.to_date_string(utils.get_days_ago_date(-2)));
    var days_ago = formated.match(/\d+天前/);
    if(days_ago != null)
    {
        formated = formated.replace(/\d+天前/, utils.to_date_string(utils.get_days_ago_date(days_ago[1])));
    }
    var days_ago = formated.match(/\d+小时前/);
    if(days_ago != null)
    {
        formated = formated.replace(/\d+小时前/, utils.to_date_string(utils.get_days_ago_date(days_ago[1])));
    }
    return Date.parse(formated);
}

utils.parse_html = function (html, replaces) {
    for(var i = 0; i < replaces.length; i++)
    {
        replacesinfo = replaces[i];
        html = html.replace(new RegExp(replacesinfo[0],"ig"), replacesinfo[1]);
    }
    return html;
}

utils.parse_html_replace_image = function (html) {
    var replaces = [
        ["\<\!DOCTYPE.*?\>", ""],
        ["<script", "<_script_"],
        ["\<\/script\>", "\<\/_script_\>"],
        ["<link.*?/>", ""],
        ["<link.*?>", ""],
        ["[^a-zA-Z\-_]?src=", " " + utils.REPLACE_SRC + "="],
        [utils.REPLACE_SRC + "=\"\"", ""]
    ];
    return utils.parse_html(html, replaces);
}

utils.DBObject = function()
{
    var content = {};
    var dirty = {};

    this.isDirty = function(key)
    {
        if(!key)
        {
            for(var i in dirty)
            {
                if(dirty[i])
                    return true;
            }
            return false;
        }
        else
        {           
            return dirty[key] != undefined;
        }
    }

    this.copyFrom = function(obj)
    {
        for(var i in obj)
        {
            content[i] = obj[i];
            dirty[i] = false;
        }
    }

    this.set = function(key, value)
    {
        content[key] = value;
        dirty[key] = false;     
    }

    this.modify = function(key, value)
    {
        if(content[key] != value)
        {
            content[key] = value;
            dirty[key] = true;  
            return true;
        }
        return false;
    }

    this.get = function(key)
    {
        if(key)
        {
            return content[key];
        }
        else
        {
            var contents = {};
            for(var i in content)
            {
                contents[i] = content[i];
            }
            return contents;
        }
    }

    this.getDirty = function(key)
    {
        if(key)
        {
            if(dirty[key])
                return content[key];
            return undefined;           
        }
        else
        {
            var dirtyObj = {};
            for(var i in dirty)
            {
                if(dirty[i])
                    dirtyObj[i] = content[i];
            }
            return dirtyObj;
        }
    }

    this.foreach = function(callback)
    {
        for(var i in content)
        {
            callback(i, content[i], dirty[i]);
        }
    }

    this.createUpdateStatment = function(table)
    {

    }
}

utils.copy = function (myObj){  
    if(typeof(myObj) != 'object' || myObj == null) return myObj;  
    var newObj = new Object();  
    for(var i in myObj){  
      newObj[i] = utils.copy(myObj[i]); 
    }  
    return newObj;  
}  

utils.REPLACE_SRC = "_src_";
module.exports = utils;