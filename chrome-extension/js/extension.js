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
SCRIPTCONTENT_API_URL = "https://scriptobservatory.org/script-content";


/*
 * Global Variables / Data Structures
 * ----------------------------------
 * (1) SCRIPTS: Maps the tabId to a list of all scripts loaded for the given tab. 
 *              - Cleared every time a request for a main_frame is made. 
 *              - Used and cleared every time the chrome.tabs.onUpdated listener fires 
 *                and data is POSTed to the API.
 *              - Cleared whenever GENERAL_REPORTING_ON is toggled to false
 *              TODO UPDATE
 * (2) GENERAL_REPORTING_ON: true if the chrome extension should report observations to the
 *                   ScriptObservatory backend, false if not.
 */
var SCRIPTS = {};
var GENERAL_REPORTING_ON = true; 
var SCRIPT_CONTENT_UPLOADING_ON = true;
var POST_IFRAME_CONTENT = true;
var scripts_to_send = [];


/*
 * GENERAL_REPORTING_ON helper functions
 * -----------------------------
 * Help with getting/setting the global reporting state and automatically performing 
 * follow-up actions needed.
 * TODO: eventually clean this up...
 */
function toggleReportingState(){
    GENERAL_REPORTING_ON = !GENERAL_REPORTING_ON;
    SCRIPTS = {};

    if (GENERAL_REPORTING_ON == false && SCRIPT_CONTENT_UPLOADING_ON == true){
        // if GENERAL_REPORTING_ON was just turned false, we want to make sure 
        // SCRIPT_CONTENT_UPLOADING_ON is also false
        toggleScriptContentUploadingState();
    }
}

function toggleScriptContentUploadingState(){
    if (SCRIPT_CONTENT_UPLOADING_ON == false && GENERAL_REPORTING_ON == false){
        // GENERAL_REPORTING_ON must be true in order to report script content!
        // TODO: explain to user
        return;
    }             
    SCRIPT_CONTENT_UPLOADING_ON = !SCRIPT_CONTENT_UPLOADING_ON;
}

function getReportingState(){ return GENERAL_REPORTING_ON; }
function getScriptContentReportingState(){ return SCRIPT_CONTENT_UPLOADING_ON; }


/*
 * httpGet(url)
 * ------------
 * Perform a HTTP GET request to *url* and return its content
 */
function httpGet(url){
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", url, false);
    xmlHttp.send();
    return xmlHttp.responseText;  // TODO: check return code
}


/*
 * httpPatch(url, data)
 * -------------------
 * Send json-ified *data* with a HTTP PATCH request to *url*. If the PATCH request
 * fails with an error code of 404, we automatically send a POST request to 
 * initialize the webpage in the ScriptObservatory API.
 */
function httpPatch(site_url, data){
    var request = new XMLHttpRequest();
    
    var url_hash = CryptoJS.SHA256(site_url).toString(CryptoJS.enc.Base64);
    var patch_data = {"pageviews": {"add": [data]} };
    var patch_url = WEBPAGE_API_URL + "/" + url_hash;
    
    console.log("finished " + site_url + " -> " + JSON.stringify(patch_data));

    request.open("PATCH", patch_url, false);
    request.setRequestHeader("Content-Type", "application/json");
    request.send(JSON.stringify(patch_data));
    
    if (request.status == 404){
        var post_data = {"id": url_hash,
                         "url": site_url,
                         "pageviews": [data]};
        
        httpPost(WEBPAGE_API_URL, post_data);
    }

    return;  // TODO: check return code
}


/*
 * httpPost(url, data)
 * -------------------
 * Send json-ified *data* with a HTTP POST request to *url*
 */
function httpPost(url, data){
    var request = new XMLHttpRequest();
    request.open("POST", url, false);
    request.setRequestHeader("Content-Type", "application/json");
    request.send(JSON.stringify(data));
    return;  // TODO: check return code
}

/*
 * scriptcontentPost(data)
 * -----------------------
 * Send json-ified script-content *data* 
 */
function scriptcontentPost(data){
    if (SCRIPT_CONTENT_UPLOADING_ON){
        console.log("posting scriptcontent " + data["sha256"]);
        httpPost(SCRIPTCONTENT_API_URL, data); 
    }
}


/* 
 * chrome.webRequest.onBeforeRequest listener
 * ------------------------------------------
 * We hook into chrome.webRequest.onBeforeRequest to keep track of the tabIds of
 * all requests for "main_frame" objects and to grab the content of requests for
 * "script" objects. 
 * 
 * For "script" requests, we perform our own download of the content and calculate
 * the sha256 hash of what we receive from the server. After the download of a 
 * "script" object is complete, if an entry is present in SCRIPTS for our current
 * tabId, we add the data we have (script URL & hash) to the SCRIPTS data structure.
 * 
 * It would be nice if we could let the browser do the request for "script" objects
 * normally and grab the content of the response it receives, but this is not
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
            data = httpGet(details.url);

            console.log(details.url + " on tabid= " + tabId + " --> " + data);

            hash = CryptoJS.SHA256(data).toString(CryptoJS.enc.Base64);

            if (tabId in SCRIPTS) {
                SCRIPTS[tabId]["scripts"].push({"url": details.url, "hash": hash});
            }
            else {
                // TODO: look into auto-reporting this error
                console.log("tabId of " + tabId + 
                            " found for " + details.url +
                            " but main_frame not found!!");
            }
            
            if (details.type == "script" || (details.type == "sub_frame" && POST_IFRAME_CONTENT)){
                if (details.url.slice(0, 13) != "inline_script"){
                    var script_content_data = {"sha256": hash, 
                                               "content": data};
                    
                    scriptcontentPost(script_content_data);      
                }
            }
            
            if (details.type == "sub_frame"){
                var el = document.createElement("html");
                el.innerHTML = data;
             
                var to_return = [];
                var scripts = el.getElementsByTagName("script");
                //console.log("got " + scripts.length + " scripts in iframe");    
            
                for (var i=0; i<scripts.length; ++i){
                    if (!scripts[i].src){
                        //console.log("got inline iframe script!");    
                        inline_script_content = String(scripts[i].innerHTML);
                        //console.log(inline_script_content);
                        hash = CryptoJS.SHA256(inline_script_content).toString(CryptoJS.enc.Base64);
                        var url = "inline_script_" + hash.slice(0,18);
                    
                        var script_content_data = {"sha256": hash, 
                                                   "content": inline_script_content};
                        scriptcontentPost(script_content_data);

                        if (tabId in SCRIPTS) {
                            SCRIPTS[tabId]["scripts"].push({"url": url, "hash": hash});
                        }
                        else {
                            // TODO: look into auto-reporting this error
                            console.log("tabId of " + tabId + 
                                        " found for " + url +
                                        " but main_frame not found!!");
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
        else if (details.type == "main_frame") {
            console.log("got main_frame request");
            if (tabId in SCRIPTS){
                console.log("we've found unsent data for this tab! --> " + JSON.stringify(SCRIPTS[tabId]));
                listener({"tabId": tabId, "url": SCRIPTS[tabId]["url"], "scripts": SCRIPTS[tabId]["scripts"]});
                SCRIPTS[tabId] = {"scripts": [], "url": details.url}; 
            }
            else {
                console.log("clearing SCRIPTS in main_frame req");
                SCRIPTS[tabId] = {"scripts": [], "url": details.url}; 
            }
            return {cancel: false}; 
        }        

        // TODO: look into auto-reporting this error...
        console.log("failed to hit a return statement!!");
    }, 
    {urls: ["http://*/*", "https://*/*"], types: ["script", "main_frame", "sub_frame"]}, 
    ["blocking"]
);


/*
 * chrome.tabs.onUpdated listener
 * ------------------------------
 * We hook into chrome.tabs.onUpdated to determine when a page load has completed. 
 *
 * We check changeInfo.status to make sure that the reason the onUpdated listener
 * was called is that the status was changed to "complete". If this is so, we 
 * inject javascript to scrape all inline script tags out of the document body.
 * We then grab those script bodies and calculate the SHA-256 hash of each of
 * them. Once we have this, we add these inline scripts to the scripts already
 * collected and send a POST request to the PAGEVIEW_API_URL with the browsing data 
 * from SCRIPTS. We then delete tabId's entry from SCRIPTS.
 */
function listener(details){
    if (GENERAL_REPORTING_ON == false){
        return {cancel: false}; 
    }

    var tabId = details.tabId;
    
    if (!(tabId in SCRIPTS)){
        console.log("in listener, but tabId not in SCRIPTS!");
        return; // check to see if it's been deleted since 
    }

    if ("scripts" in details && typeof details["scripts"] != 'undefined'){
        // we were triggered by a main_frame request
        /*if (SCRIPTS[tabId]["locked"]){
            console.log("tabId has been locked!");
            return;
        }*/

        console.log("in listener() because of a main_frame request, details.url= " + details.url + " SCRIPTS[tabId][url]= " + SCRIPTS[tabId]["url"]);
        scripts_to_send = details.scripts;
        console.log(JSON.stringify(scripts_to_send) + " <-- sts");
    }
    else {
        // we were triggered by onCompleted
        console.log("in listener() because of onCompleted, details.url= " + details.url + " SCRIPTS[tabId][url]= " + SCRIPTS[tabId]["url"]);
        if (details.url != SCRIPTS[tabId]["url"]){
            console.log("skipping this one");
            return; 
        }
        scripts_to_send = SCRIPTS[tabId]["scripts"];
        delete SCRIPTS[tabId];
        console.log(" .. now clearing SCRIPTS in listener()");
        console.log(JSON.stringify(scripts_to_send) + " <-- sts");
    }

    // TODO: review this injected code for possible security issues before making
    //       release. OK for now as it's just the robo-browser using this code.
    injected_code = "var to_return = []; var scripts = " +
            "document.getElementsByTagName('script'); for (var i=0; " +
            "i<scripts.length; i++) { if(!scripts[i].src) to_return.push( " +
            "scripts[i].innerHTML ); }; to_return";

    chrome.tabs.executeScript(tabId, 
                              {code: injected_code, runAt: "document_start"},
                              function(scripts){
        /*
        if (!(tabId in SCRIPTS)){
            console.log("in inline_callback, but tabId not in SCRIPTS!");
            return; // check to see if it's been deleted since 
        }
        */
        console.log(" in inline_callback(), scripts = " + JSON.stringify(scripts) + " --> " + Object.prototype.toString.call( scripts ));
        if (Object.prototype.toString.call( scripts ) == '[object Undefined]') return;
        if (Object.prototype.toString.call( scripts[0] ) == '[object Undefined]'){
            console.log("scripts[0] was undefined! returning.");
            return;
        }
        scripts = scripts[0];

        var arrayLength = scripts.length;
        for (var i = 0; i < arrayLength; i++) {
            data = String(scripts[i]);
            hash = CryptoJS.SHA256(data).toString(CryptoJS.enc.Base64);
            var url = "inline_script_" + hash.slice(0,18);
            scripts_to_send.push({"url": url, "hash": hash});
        
            var script_content_data = {"sha256": hash, 
                                       "content": data};
    
            scriptcontentPost(script_content_data);
        }

        var timeStamp = new Date().getTime();
        var pageview_data = {"scripts": scripts_to_send};

        console.log("on " + details.url + " we saw " + pageview_data["scripts"]);
        /*
        if (SCRIPTS[tabId]["locked"]){
            console.log("tabId has been locked!");
            return;
        }*/

        httpPatch(details.url, pageview_data);
    });

    console.log("we've run executeScript()");
}


chrome.webNavigation.onCompleted.addListener(listener);
