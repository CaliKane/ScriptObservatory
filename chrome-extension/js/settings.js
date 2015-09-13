/*
 *
 * This file (settings.js) implements all settings-related functionality for the 
 * ScriptObservatory Chrome extension. 
 *
 * This JavaScript code is loaded into the "background page" Chrome sets up 
 * for the extension. 
 *
 */


/* 
 * Constants
 */
DEFAULT_UPLOAD_BLACKLIST = [new RegExp("^https?:\\/\\/www.google.com\\/maps", 'i')];
MAX_CONTENT_QUEUE_LENGTH = 9;


/*
 * Global Variables / Data Structures
 */
var GENERAL_REPORTING_ON = true; 
var CONTENT_UPLOADING_ON = true;
var POST_IFRAME_CONTENT = true;
var UPLOAD_BLACKLIST = [];


/*
 * Helper Functions for General Settings 
 * -------------------------------------
 * Help with getting/setting/maintaining the global reporting state 
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

