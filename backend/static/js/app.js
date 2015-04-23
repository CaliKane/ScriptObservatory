/*
 * app.js is the main JavaScript code for the website. It includes some generic
 * JavaScript as well as some AngularJS code.
 */

/* 
 * visualization helper functions
 *  (these should be deleted when the page moves to bootstrap)
 */
function show_about(){
    document.getElementById('info_section').style.display="block";
    document.getElementById('website_query_section').style.display="none";
    document.getElementById('script_query_section').style.display="none";
}

function showWebsiteQueryResults(){    
    document.getElementById('info_section').style.display="none";
    document.getElementById('website_query_section').style.display="block";
    document.getElementById('script_query_section').style.display="none";
}

function showScriptQueryResults(){
    document.getElementById('info_section').style.display="none";
    document.getElementById('website_query_section').style.display="none";
    document.getElementById('script_query_section').style.display="block";
}


/* 
 * add a repeat(n) method to String objects so we can get a String of 
 * a substring repeated *n* times.
 */
String.prototype.repeat = function(num){
    return new Array( num + 1 ).join( this );
}

/* 
 * add a contains(k) method to Array objects, so we can check if 
 * element *k* exists in a given array.
 */
Array.prototype.contains = function(k) {
    for(var i=0; i < this.length; i++){
        if(this[i] === k){
            return true;
        }
    }
    return false;
}


function isValidHash(str) {
    var l = str.length;
    for (i = 0; i < l; ++i){
        val = str.charCodeAt(i);
        if ((val < 97 && val > 122) && (val < 48 && val > 57)) return false;
    }
    return true;
}


/* 
 * AngularJS app definition
 */
var app = angular.module("app", ['ui.bootstrap']);

  
/*
 * add object2Array filter to let us sort Objects from Angular in the 
 * same way we sort Arrays.
 */ 
app.filter('object2Array', function() {
    return function(input) {
        var out = []; 
        for(i in input){
            out.push(input[i]);
        }
        return out;
    }
});


app.controller("AppCtrl", function($http, $scope, $modal){
    var app = this;
    $scope.openWebsite = function (site) {
      var modalInstance = $modal.open({
        templateUrl: 'websiteModalContent.html',
        controller: 'ModalInstanceCtrl',
        size: 'lg',
        resolve: {
          currentObj: function () {
            return site;
          },
          webpageUrl: function () {
            return site.url;
          },
          scriptUrl: function () {
            return "";
          },
          openWebsite: function() {
            return $scope.openWebsite;
          },
          openScript: function() {
            return $scope.openScript;
          },
          openHash: function() {
            return $scope.openHash;
          }
        }
      });
    };

    $scope.openScript = function (script, webpageUrl) {
      var modalInstance = $modal.open({
        templateUrl: 'scriptModalContent.html',
        controller: 'ModalInstanceCtrl',
        size: 'lg',
        resolve: {
          currentObj: function () {
            return script;
          },
          webpageUrl: function () {
            return webpageUrl;
          },
          scriptUrl: function () {
            return script.url;
          },
          openWebsite: function() {
            return $scope.openWebsite;
          },
          openScript: function() {
            return $scope.openScript;
          },
          openHash: function() {
            return $scope.openHash;
          }
        }
      });
    };


    $scope.openHash = function (hash, scriptUrl, webpageUrl) {
      var modalInstance = $modal.open({
        templateUrl: 'hashModalContent.html',
        controller: 'ModalInstanceCtrl',
        size: 'lg',
        resolve: {
          currentObj: function () {
            return hash;
          },
          webpageUrl: function () {
            return webpageUrl;
          },
          scriptUrl: function () {
            return scriptUrl;
          },
          openWebsite: function() {
            return $scope.openWebsite;
          },
          openScript: function() {
            return $scope.openScript;
          },
          openHash: function() {
            return $scope.openHash;
          }
        }
      });
    };

    $scope.submitUrlSuggestionForm = function(urls){
        console.log("got submission for " + urls);

        var data = {'content': urls}
        var request = new XMLHttpRequest();
        request.open("POST", "/api/suggestions", false);
        request.setRequestHeader("Content-Type", "application/json");
        request.send(JSON.stringify(data));
        console.log(request.status);

        alert("Your list has been submitted. Thank you!");
        return;  // TODO: check return code
    }



    $scope.submitUrlSubmissionForm = function(url){
        console.log("got submission for " + url);
     
        if (url.slice(0,7) != "http://" && url.slice(0,8) != "https://") {
            url = "http://" + url;
        }
   
        console.log("url= " + url);

        var data = {'url': url, 'priority': 1}
        var request = new XMLHttpRequest();
        request.open("POST", "/api/robotask", false);
        request.setRequestHeader("Content-Type", "application/json");
        request.send(JSON.stringify(data));
        console.log(request.status);

        var data = {'content': url}
        var request = new XMLHttpRequest();
        request.open("POST", "/api/suggestions", false);
        request.setRequestHeader("Content-Type", "application/json");
        request.send(JSON.stringify(data));
        console.log(request.status);

        alert("Your URL has been submitted.");
        return;  // TODO: check return code
    }


    $scope.check_for_query_params = function(){
        var queryDict = {}
        location.search.substr(1).split("&").forEach(function(item) {queryDict[item.split("=")[0]] = item.split("=")[1]})
        
        if ("query" in queryDict){
            var q = queryDict["query"];
            $scope.submitQueryForm(q);
            $scope.explore_tab = true;
        }
    }

    // make "all" the default time range choice
    $scope.dateRangeChoice = "all";

    $scope.submitQueryForm = function(queryText){
        var query = queryText;

        var data = {'content': query}
        var request = new XMLHttpRequest();
        request.open("POST", "/api/suggestions", false);
        request.setRequestHeader("Content-Type", "application/json");
        request.send(JSON.stringify(data));

        $scope.submitQuery(query);
    }

    $scope.submitQuery = function(query){
        var date_option = $scope.dateRangeChoice;

        var current_time = (new Date()).getTime();
        var min_time = 0;
        
        if (date_option == "year"){
            min_time = current_time - (1000*60*60*24*365);
        }
        else if (date_option == "month"){
            min_time = current_time - (1000*60*60*24*30);
        }
        else if (date_option == "week"){
            min_time = current_time - (1000*60*60*24*7);
        }
        else if (date_option == "day"){
            min_time = current_time - (1000*60*60*24);
        }
 
        var query_string = "";

        if (query != "") {
            if (query.length == 64 && isValidHash(query)){
                // this is a hash query
                queryString = '?q={"filters":[{"name":"script_hash","op":"eq","val":"' + query + '"}]}';
                $scope.makeScriptQueryByHash(queryString);
                showScriptQueryResults();
            }
            else if (query.slice(-3) == ".js" || query.slice(0, 14) == "inline_script_"){
                // this is a javascript query
                queryString = '?q={"filters":[{"name":"script_url","op":"eq","val":"' + query + '"}]}';
                $scope.makeScriptQueryByUrl(queryString);
                showScriptQueryResults();
            }
            else {
                // this is a webpage query
                /* 
                 * if the last character in the URL is a /, we strip it off because we allow
                 * a single character following the query string to be any character to avoid missing
                 * results from www.google.com/ when the user enters www.google.com & results from 
                 * www.google.com when the user enters www.google.com/
                 */
                if (query.slice(-1) == '/'){
                    query = query.slice(0, -1);
                }
                queryString = '?q={"filters":[{"and":[{"name":"url","op":"like","val":"%' + query + '%"},{"name":"date","op":">=","val":"' + min_time + '"}]}]}';
                $scope.makeWebpageQuery(queryString);
                showWebsiteQueryResults();
            }
            //queryString = '?q={"filters":[{"and":[{"or":[{"name":"url","op":"like","val":"%' + query + '_"},{"name":"scripts__url","op":"any","val":"' + query + '"},{"name":"scripts__hash","op":"any","val":"' + query + '"}]},{"name":"date","op":">=","val":"' + min_time + '"}]}]}';
            //queryString = '?q={"filters":[{"name":"url","op":"like","val":"%' + query + '_"}]}';
        }
    }

    $scope.makeScriptQueryByUrl = function(queryString){
        $http.get("/api/scripturlindex" + queryString).success(function (data){
            app.scriptQueryResults = data.objects[0].page_urls.split(',');
        });
    }

    $scope.makeScriptQueryByHash = function(queryString){
        $http.get("/api/scripthashindex" + queryString).success(function (data){
            app.scriptQueryResults = data.objects[0].page_urls.split(',');
        });
    }

    $scope.makeWebpageQuery = function(queryString){
        $http.get("/api/pageview" + queryString).success(function (data){
            app.records = data.objects;
               
            app.sites = [];
            seen_urls = [];
            already_seen = [];

            for (var i = 0; i < app.records.length; i++){
                var cur_record = app.records[i];

                // TEMPORARY
                if (already_seen.contains(cur_record.url)) continue;
                already_seen.push(cur_record.url);
                // end TEMPORARY

                var to_add = {"url": cur_record.url,
                              "occur": 0,
                              "scripts": {}};
                
                for (var j = i; j < app.records.length; j++){
                    if (app.records[j].url == to_add.url){
                        to_add.occur += 1;
    
                        for (var script_ind = 0; script_ind < app.records[j].scripts.length; script_ind++){
                            var script_url = app.records[j].scripts[script_ind].url;
                            var script_hash = app.records[j].scripts[script_ind].hash;

                            if (!(script_url in to_add.scripts)){
                                to_add.scripts[script_url] = {};
                                to_add.scripts[script_url].url = script_url; // might not be necessary
                                to_add.scripts[script_url].hashes = {};
                                to_add.scripts[script_url].occur = 0;
                            }
                            
                            if (!(script_hash in to_add.scripts[script_url].hashes)){
                                to_add.scripts[script_url].hashes[script_hash] = {};
                                to_add.scripts[script_url].hashes[script_hash].hash = script_hash; // might not be necessary
                                to_add.scripts[script_url].hashes[script_hash].occur = 0;
                            }
                            
                            to_add.scripts[script_url].occur += 1;
                            to_add.scripts[script_url].hashes[script_hash].occur += 1;
                        }
                    }
                }

                // convert hash occur values to percentages
                for (var script_url in to_add.scripts){
                    for (var hash_val in to_add.scripts[script_url].hashes){
                        to_add.scripts[script_url].hashes[hash_val].occur *= (100.0 / to_add.scripts[script_url].occur);
                    }
                    
                    to_add.scripts[script_url].occur *= (100.0 / to_add.occur);
                }

                app.sites.push(to_add);
            }
            
        });
    }

    setTimeout($scope.check_for_query_params, 50);
});


app.controller('ModalInstanceCtrl', function ($scope, $modalInstance, currentObj, scriptUrl, webpageUrl, openWebsite, openScript, openHash) {
  $scope.currentObj = currentObj;

  $scope.scriptUrl = scriptUrl;
  $scope.webpageUrl = webpageUrl;
 
  $scope.openObj = function(obj, type, webpageUrl, scriptUrl){
    if (type == "website") openWebsite(obj);
    else if (type == "script") openScript(obj, webpageUrl);
    else if (type == "hash") openHash(obj, scriptUrl, webpageUrl);
  }

  $scope.ok = function () {
    $modalInstance.close();
  };
});
