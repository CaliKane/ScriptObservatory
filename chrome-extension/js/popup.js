/*
 * This contains all helper JS code for the popup menu
 */
//use strict;
var bp = chrome.extension.getBackgroundPage();
var BASE_QUERY_URL = "https://scriptobservatory.org/search/?query="


function e(id) {
    return document.getElementById(id);
}


function jumpToAnalysisPage(){
    function redirectToActiveTabUrl(tabs){
        chrome.tabs.update(null, {url: BASE_QUERY_URL + encodeURIComponent(tabs[0].url)});
    };

    chrome.tabs.query({active: true, currentWindow: true}, redirectToActiveTabUrl);
}


function updateReportingStatusDisplay(){
    if (bp.getReportingState()){
        e("current-reporting-status").innerHTML = "Reporting is ON";
        e("toggle-reporting-status").innerHTML = "Turn Observation Reporting Off";
    }
    else {
        e("current-reporting-status").innerHTML = "Reporting is OFF";
        e("toggle-reporting-status").innerHTML = "Turn Observation Reporting On";
    }
    
    if (bp.getScriptContentReportingState()){
        e("toggle-sc-uploading-status").innerHTML = "Turn Script Content Uploading Off";
        e("current-sc-uploading-status").innerHTML = "Script Content Uploading is ON";
    }
    else{
        e("toggle-sc-uploading-status").innerHTML = "Turn Script Content Uploading On";
        e("current-sc-uploading-status").innerHTML = "Script Content Uploading is OFF";
    }
}
    
function toggleReportingStatus(){
    bp.toggleReportingState();
    updateReportingStatusDisplay();
}

function toggleSCUploadingStatus(){
    bp.toggleScriptContentUploadingState();
    updateReportingStatusDisplay();
}


e("analyze-current-page").addEventListener("click", jumpToAnalysisPage);
e("toggle-reporting-status").addEventListener("click", toggleReportingStatus);
e("toggle-sc-uploading-status").addEventListener("click", toggleSCUploadingStatus);


updateReportingStatusDisplay();

