/*
 *
 * This file (extension.js) implements all non-crypto functionality for the 
 * ScriptObservatory Chrome extension. 
 *
 * External code used is used to calculate SHA-256 hashes (sha256.js).
 *
 * This JavaScript code is loaded into the "background page" Chrome sets up 
 * for the extension. 
 *
 */


/* 
 * Constants
 */
WEBPAGE_API_URL = "https://scriptobservatory.org/api/webpage";
PAGEVIEW_API_URL = "https://scriptobservatory.org/api/pageview";
CONTENT_API_URL = "https://scriptobservatory.org/api/resource-content";


/*
 * Global Variables / Data Structures
 * ----------------------------------
 * - RESOURCES: Maps the tabId to a dictionary containing the tab's URL and loaded JavaScript
 * - GENERAL_REPORTING_ON: true if chrome extension should report observations to the backend
 * - resources_to_send --> temporarily global until refactor (TODO)
 */
var RESOURCES = {};
var CONTENT_QUEUE = {};
var GENERAL_REPORTING_ON = true; 
var CONTENT_UPLOADING_ON = true;
var POST_IFRAME_CONTENT = true;
var UPLOAD_BLACKLIST = [];
var DEFAULT_UPLOAD_BLACKLIST = [new RegExp("^https?:\\/\\/www.google.com\\/maps", 'i')];
var resources_to_send = [];
var MAX_CONTENT_QUEUE_LENGTH = 9;


/*
 * Helper Functions for General Settings 
 * -------------------------------------
 * Help with getting/setting/maintaining the global reporting state 
 * 
 * TODO: eventually refactor and move all this to separate JS file
 */
function toggleReportingState(){
    GENERAL_REPORTING_ON = !GENERAL_REPORTING_ON;
    RESOURCES = {};

    if (GENERAL_REPORTING_ON == false && CONTENT_UPLOADING_ON == true){
        // if GENERAL_REPORTING_ON was just turned false, we want to make sure 
        // CONTENT_UPLOADING_ON is also false
        toggleScriptContentUploadingState();
    }

    setSettings();
}

function toggleScriptContentUploadingState(){
    if (CONTENT_UPLOADING_ON == false && GENERAL_REPORTING_ON == false){
        // GENERAL_REPORTING_ON must be true in order to report script content!
        return;
    }             
    CONTENT_UPLOADING_ON = !CONTENT_UPLOADING_ON;

    setSettings();
}

function getReportingState(){ 
    return GENERAL_REPORTING_ON;
}

function getScriptContentReportingState(){
    return CONTENT_UPLOADING_ON;
}

function getFilters(){
    return UPLOAD_BLACKLIST.map(regexArrayToStrings);
}

function addFilter(filter){
    // TODO: validate
    filter = new RegExp(filter, "i");

    if (UPLOAD_BLACKLIST.indexOf(filter) == -1){
        UPLOAD_BLACKLIST.push(filter);
        setSettings();
    }
}

function removeFilter(filter_ind){
    UPLOAD_BLACKLIST.splice(parseInt(filter_ind), 1);
    setSettings();
}

function setSettings(){
    // TODO: rename 
    chrome.storage.sync.set({'GENERAL_REPORTING_ON': GENERAL_REPORTING_ON,
                             'CONTENT_UPLOADING_ON': CONTENT_UPLOADING_ON,
                             'POST_IFRAME_CONTENT': POST_IFRAME_CONTENT,
                             'UPLOAD_BLACKLIST': UPLOAD_BLACKLIST.map(regexArrayToStrings)}, 
                            function(){
                                console.log("finished with setSettings() call");
                            });
}

function isEmpty(obj) {
    return Object.keys(obj).length === 0;
}

function getSettings(){
    chrome.storage.sync.get('GENERAL_REPORTING_ON', function(items) {
        if (isEmpty(items)){ 
            console.log("no stored GENERAL_REPORTING_ON value found, defaulting to True.");
            GENERAL_REPORTING_ON = true;
        }
        else { 
            console.log("GENERAL_REPORTING_ON --> " + JSON.stringify(items));
            GENERAL_REPORTING_ON = items["GENERAL_REPORTING_ON"];
        }
    });
    
    chrome.storage.sync.get('CONTENT_UPLOADING_ON', function(items) {
        if (isEmpty(items)){ 
            console.log("no stored CONTENT_UPLOADING_ON value found, defaulting to True."); 
            CONTENT_UPLOADING_ON = true;
        }
        else { 
            console.log("CONTENT_UPLOADING_ON --> " + JSON.stringify(items));
            CONTENT_UPLOADING_ON = items["CONTENT_UPLOADING_ON"];
        }
    });
    
    chrome.storage.sync.get('POST_IFRAME_CONTENT', function(items) {
        if (isEmpty(items)){ 
            console.log("no stored POST_IFRAME_CONTENT value found, defaulting to True."); 
            POST_IFRAME_CONTENT = true;
        }
        else { 
            console.log("POST_IFRAME_CONTENT --> " + JSON.stringify(items));
            POST_IFRAME_CONTENT = items["POST_IFRAME_CONTENT"];
        } 
    });

    chrome.storage.sync.get('UPLOAD_BLACKLIST', function(items) {
        if (isEmpty(items)){ 
            UPLOAD_BLACKLIST = DEFAULT_UPLOAD_BLACKLIST;
            console.log("no stored UPLOAD_BLACKLIST value found, defaulting to " + UPLOAD_BLACKLIST.map(regexArrayToStrings)); 
        }
        else { 
            UPLOAD_BLACKLIST = items["UPLOAD_BLACKLIST"].map(stringArrayToRegexes);
            console.log("UPLOAD_BLACKLIST --> " + UPLOAD_BLACKLIST.map(regexArrayToStrings));
        }
    });
}

function stringArrayToRegexes(cur_val, ind, arr){
    // we always do case-insensitive regexes
    return new RegExp(cur_val, 'i');
}

function regexArrayToStrings(cur_val, ind, arr){
    // we strip off the leading / and trailing /i (hacky, but ok for now)
    var str = cur_val.toString()
    return str.substr(1, str.length - 3);
}

getSettings();

/*
 * httpGet(url)
 * ------------
 * Perform a HTTP GET request to *url* and return its content
 *
 * TODO: check return code & callback-ify this and make it asynchronous
 */
function httpGet(url){
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", url, false);
    xmlHttp.send();
    return xmlHttp.responseText;  
}

/*
 * httpPatch(url, data)
 * -------------------
 * Send json-ified *data* with a HTTP PATCH request to *url*. If the PATCH request
 * fails with an error code of 404, we automatically send a POST request to 
 * initialize the webpage in the ScriptObservatory API.
 *
 * TODO: check return code & callback-ify this and make it asynchronous
 */
function httpPatch(site_url, data){
    for (var i=0; i<UPLOAD_BLACKLIST.length; ++i){
        if (site_url.match(UPLOAD_BLACKLIST[i])){
            console.log("we were going to send a PATCH, but " + site_url + " matches " + UPLOAD_BLACKLIST[i] + " in UPLOAD_BLACKLIST!");
            return;
        }    
    }
    
    var url_hash = CryptoJS.SHA256(site_url).toString(CryptoJS.enc.Base64);
    var patch_data = {"pageviews": {"add": [data]} };
    var patch_url = WEBPAGE_API_URL + "/" + url_hash;
    
    console.log("finished " + site_url + " -> " + JSON.stringify(patch_data));

    var request = new XMLHttpRequest();
    request.open("PATCH", patch_url, false);
    request.setRequestHeader("Content-Type", "application/json");
    request.send(JSON.stringify(patch_data));
    
    if (request.status == 404){
        httpPost(WEBPAGE_API_URL, {"id": url_hash, "url": site_url, "pageviews": [data]});
    }
    
    contentFlushQueue();
}

/*
 * httpPost(url, data)
 * -------------------
 * Send json-ified *data* with a HTTP POST request to *url*
 *
 * WARNING: this should only be invoked via httpPatch or contentPost!
 *           (UPLOAD_BLACKLIST checks take place there, instead!)
 *
 * TODO: check return code & callback-ify this and make it asynchronous
 */
function httpPost(url, data){
    var request = new XMLHttpRequest();
    request.open("POST", url, false);
    request.setRequestHeader("Content-Type", "application/json");
    request.send(JSON.stringify(data));
}


/*
 * contentQueue(data)
 * ------------------------
 * Queue json-ified content *data* to be sent later, with the 
 * send action triggered by a contentFlushQueue() call.
 */
function contentQueue(data, seen_on){
    if (CONTENT_UPLOADING_ON){
        for (var i=0; i<UPLOAD_BLACKLIST.length; ++i){
            if (seen_on.match(UPLOAD_BLACKLIST[i])){
                console.log("we were going to queue a content, but " + seen_on + " matches " + UPLOAD_BLACKLIST[i] + " in UPLOAD_BLACKLIST!");
                return;
            }
        }
        
        CONTENT_QUEUE[data["sha256"]] = data["content"];

        if (Object.keys(CONTENT_QUEUE).length > MAX_CONTENT_QUEUE_LENGTH){
            contentFlushQueue();
        }
    }
}


/*
 * contentFlushQueue()
 * -----------------------
 * Go through everything stored in CONTENT_QUEUE and send it
 * off to *CONTENT_API_URL*.
 *
 * TODO: make asynchronous
 *
 */
function contentFlushQueue(){
    if (Object.keys(CONTENT_QUEUE).length == 0){
        return;
    }

    var url = CONTENT_API_URL + "?hashes=" + Object.keys(CONTENT_QUEUE).join(",");
    var resp = JSON.parse(httpGet(url));

    var newScriptContent = [];
    for (var key in resp){
        if (resp[key] == "false"){
            newScriptContent.push({"sha256": key, "content": CONTENT_QUEUE[key]});
        }
    }
    
    if (newScriptContent.length > 0){
        httpPost(CONTENT_API_URL, {"upload": newScriptContent});
    }

    CONTENT_QUEUE = {};
}


/* 
 * chrome.webRequest.onBeforeRequest listener
 * ------------------------------------------
 * We hook into chrome.webRequest.onBeforeRequest to keep track of the tabIds for
 * all requests for "main_frame" objects and to grab the content of requests for
 * "script" and "sub_frame" objects. 
 * 
 * For "script" and "sub_frame" requests, we perform our own download of the content 
 * and calculate the sha256 hash of what we receive from the server. After the download 
 * of the object is complete, if an entry is present in RESOURCES for our current
 * tabId, we add the data we have (script URL & hash) to it.
 * 
 * It would be nice if we could let the browser make the normal request for these 
 * objects and let us grab the content of the response it receives, but this is not
 * currently possible with the APIs chrome exposes to extensions. We're stuck 
 * injecting in this non-optimal way for now.
 * 
 * This functionality is discussed in the following issue: 
 *   http://code.google.com/p/chromium/issues/detail?id=104058
 * 
 * A draft proposal for adding this functionality is here: 
 *   http://groups.google.com/a/chromium.org/forum/#!msg/apps-dev/v176iCmRgSs/iM-72Evf8JgJ
 *
 * More general information is available in the chrome.webRequest docs: 
 *   http://developer.chrome.com/extensions/webRequest
 */

chrome.webRequest.onBeforeRequest.addListener(
    function(details) {
        if (GENERAL_REPORTING_ON == false){
            return {cancel: false}; 
        }

        var tabId = details.tabId;
        var data = "";
        var hash = "";

        if (details.type == "script" || details.type == "sub_frame") {
            // Get our own copy of the data
            data = httpGet(details.url);
            hash = CryptoJS.SHA256(data).toString(CryptoJS.enc.Base64);

            // Add the data & hash to our RESOURCES record:
            if (tabId in RESOURCES) {
                RESOURCES[tabId]["resources"].push({"url": details.url, "hash": hash, "type": details.type});
            }
            else {
                // TODO: look into auto-reporting this error
                console.log("no main_frame found for " + details.url + " on tabId " + tabId);
            }
            
            // Upload the content to the content API:
            if (details.type == "script" || (details.type == "sub_frame" && POST_IFRAME_CONTENT)){
                if (details.url.slice(0, 13) != "inline_script"){ /// <-- this may not be necessary TODO
                    contentQueue({"sha256": hash, "content": data}, RESOURCES[tabId]["url"]);
                }
            }
            
            // If it's an iframe, we need to search through it for JavaScript tags:
            if (details.type == "sub_frame"){
                var el = document.createElement("html");
                el.innerHTML = data;
                var scripts = el.getElementsByTagName("script");
            
                for (var i=0; i<scripts.length; ++i){
                    if (!scripts[i].src){
                        inline_script_content = String(scripts[i].innerHTML);
                        hash = CryptoJS.SHA256(inline_script_content).toString(CryptoJS.enc.Base64);
                        var url = "inline_script_" + hash.slice(0,18);
                        var script_content_data = {"sha256": hash, "content": inline_script_content};
                        
                        contentQueue(script_content_data, RESOURCES[tabId]["url"]);

                        if (tabId in RESOURCES) {
                            RESOURCES[tabId]["resources"].push({"url": url, "hash": hash, "type": details.type});
                        }
                        else {
                            // TODO: look into auto-reporting this error
                            console.log("no main_frame found for " + details.url + " on tabId " + tabId);
                       }
                    }
                }
                return {cancel: false}; // this is inefficient, but returning the content b64-encoded 
                                        // results in no JS getting run in the child IFRAME
                                        // TODO: debug
            }
             
            var data_uri = window.btoa(unescape(encodeURIComponent(data)));
            return {"redirectUrl":"data:text/html;base64, " + data_uri};
        }
        
        if (details.type == "main_frame") {
            if (tabId in RESOURCES){
                /* If we see a main_frame request go out while we RESOURCES[tabId] is still defined, something
                 * strange must have happened... for example, a piece of javascript dropped code that changes
                 * window.location, or the user started navigating to a new webpage before the current page
                 * finished loading. 
                 *
                 * We want to handle these cases by still uploading their observations, so we invoke our 
                 * onCompleteListener in a (hacky) way to mimic what would happen if that page were to finish 
                 * loading on its own.
                 */
                onCompleteListener({"tabId": tabId, "url": RESOURCES[tabId]["url"], "resources": RESOURCES[tabId]["resources"]});
            }
            
            // clear tabId's entry in RESOURCES and let the main_frame request go through unaltered
            RESOURCES[tabId] = {"resources": [], "url": details.url}; 
            return {cancel: false}; 
        }        

        console.log("failed to hit a return statement!!");  // TODO: auto-report this error
    }, 
    {urls: ["http://*/*", "https://*/*"], types: ["script", "main_frame", "sub_frame"]}, 
    ["blocking"]
);


/*
 * chrome.webNavigation.onCompleted listener (onCompleteListener())
 * ----------------------------------------------------------------
 * We hook into chrome.webNavigation.onCompleted to determine when a page load has finished.
 *
 * We inject javascript to scrape all inline script tags out of the document body.
 * We then grab those script bodies and calculate the SHA-256 hash of each of
 * them. Once we have this, we add these inline scripts to the scripts already
 * collected and send a POST request to the PAGEVIEW_API_URL with the browsing data 
 * from RESOURCES. 
 */

var onCompleteListener = function(details){
    if (GENERAL_REPORTING_ON == false){
        return {cancel: false}; 
    }

    var tabId = details.tabId;
    
    if (!(tabId in RESOURCES)){
        // TODO: look into auto-reporting this error...
        console.log("in listener, but tabId not in RESOURCES!");
        return;
    }

    if ("resources" in details && typeof details["resources"] != 'undefined'){
        // we were triggered by a main_frame request
        // TODO: hacky & should be refactored
        resources_to_send = details.scripts;
    }
    else {
        // we were triggered by onCompleted
        if (details.url != RESOURCES[tabId]["url"]){
            console.log("a main_frame request has already caused us to upload this pageview");
            return; 
        }
        resources_to_send = RESOURCES[tabId]["resources"];
        delete RESOURCES[tabId];
    }

    // TODO: Review this injected code for possible security issues before making
    //       release. OK for now as it's just the robo-browser using this code.
    //       The google page says to watch out for XSS but doesn't give more details.
    injected_code = "var to_return = []; var scripts = " +
            "document.getElementsByTagName('script'); for (var i=0; " +
            "i<scripts.length; i++) { if(!scripts[i].src) to_return.push( " +
            "scripts[i].innerHTML ); }; to_return";

    chrome.tabs.executeScript(tabId, {code: injected_code, runAt: "document_start"}, function(scripts){
        if (Object.prototype.toString.call( scripts ) != '[object Undefined]' && 
            Object.prototype.toString.call( scripts[0] ) != '[object Undefined]'){ 
            scripts = scripts[0];

            var arrayLength = scripts.length;
            for (var i = 0; i < arrayLength; i++) {
                var data = String(scripts[i]);
                var hash = CryptoJS.SHA256(data).toString(CryptoJS.enc.Base64);
                var url = "inline_script_" + hash.slice(0,18);
                
                resources_to_send.push({"url": url, "hash": hash, "type": "script"});
                contentQueue({"sha256": hash, "content": data}, details.url);
            }

            httpPatch(details.url, {"resources": resources_to_send});
        }
    });
};

chrome.webNavigation.onCompleted.addListener(onCompleteListener);
