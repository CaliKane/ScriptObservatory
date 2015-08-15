/*
 * app.js is the main JavaScript code for the website. It includes generic
 * JavaScript as well as some AngularJS code.
 */


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


function getLength(obj) {
    return Object.keys(obj).length;
}


/* 
 * AngularJS app definition
 */
var app = angular.module("app", ['ui.bootstrap']);

app.config(['$interpolateProvider', function($interpolateProvider) {
  $interpolateProvider.startSymbol('{[');
  $interpolateProvider.endSymbol(']}');
}]);
  

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
          resourceUrl: function () {
            return "";
          },
          openWebsite: function() {
            return $scope.openWebsite;
          },
          openResource: function() {
            return $scope.openResource;
          },
          openHash: function() {
            return $scope.openHash;
          }
        }
      });
    };

    $scope.openResource = function (resource, webpageUrl) {
      var modalInstance = $modal.open({
        templateUrl: 'resourceModalContent.html',
        controller: 'ModalInstanceCtrl',
        size: 'lg',
        resolve: {
          currentObj: function () {
            return resource;
          },
          webpageUrl: function () {
            return webpageUrl;
          },
          resourceUrl: function () {
            return resource.url;
          },
          openWebsite: function() {
            return $scope.openWebsite;
          },
          openResource: function() {
            return $scope.openResource;
          },
          openHash: function() {
            return $scope.openHash;
          }
        }
      });
    };


    $scope.openHash = function (hash, resourceUrl, webpageUrl) {
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
          resourceUrl: function () {
            return resourceUrl;
          },
          openWebsite: function() {
            return $scope.openWebsite;
          },
          openResource: function() {
            return $scope.openResource;
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
        /*
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
        */
        var query_string = "";

        if (query != "") {
            if (query.length == 64 && isValidHash(query)){
                // this is a hash query
                $scope.makeResourceQueryByHash(query);
            }
            else if (query.slice(-3) == ".js" || query.slice(0, 14) == "inline_script_"){
                // this is a javascript query
                $scope.makeResourceQueryByUrl(query);
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
                
                //queryString = '?q={"filters":[{"and":[{"name":"url","op":"like","val":"%' + query + '%"},{"name":"date","op":">=","val":"' + min_time + '"}]}]}';
                $scope.makeWebpageQuery(query);
                //showWebsiteQueryResults();
            }
        }
    }

    // STATUS OPTIONS:
    //  WAITING_FOR_QRY, PROCESSING_QRY, NO_RESULTS, HAVE_WEBPAGE_RESULTS, HAVE_SCRIPT_RESULTS_URL, HAVE_SCRIPT_RESULTS_HASH, QRY_ERROR
    $scope.QRY_STATUS = "WAITING_FOR_QRY";

    $scope.SCRIPT_QRY_TIMEOUT = 10*1000;
    $scope.WEBPAGE_QRY_TIMEOUT = 45*1000;

    $scope.makeResourceQueryByUrl = function(queryString){
        $scope.QRY_STATUS = "PROCESSING_QRY";
        app.resourceQuery = queryString;

        $http.get("/api/search?resource_by_url=" + queryString, {timeout: $scope.SCRIPT_QRY_TIMEOUT}).success(function (data){
            if (data.objects.length == 0){
                $scope.QRY_STATUS = "NO_RESULTS";
            }
            else {
                $scope.QRY_STATUS = "HAVE_SCRIPT_RESULTS_URL";
            }

            app.resourceQueryResults = data.objects;
        }).error(function(data){
            $scope.QRY_STATUS = "QRY_ERROR";
        });
    }

    $scope.makeResourceQueryByHash = function(queryString){
        $scope.QRY_STATUS = "PROCESSING_QRY";
        app.resourceQuery = queryString;
        
        $http.get("/api/search?resource_by_hash=" + queryString, {timeout: $scope.SCRIPT_QRY_TIMEOUT}).success(function (data){
            if (data.objects.length == 0){
                $scope.QRY_STATUS = "NO_RESULTS";
            }
            else {
                $scope.QRY_STATUS = "HAVE_SCRIPT_RESULTS_HASH";
            }
            app.resourceQueryResults = data.objects;
        });
    }

    $scope.makeWebpageQuery = function(queryString){
        $scope.QRY_STATUS = "PROCESSING_QRY";
        
        $http.get("/api/search?url=" + queryString, {timeout: $scope.WEBPAGE_QRY_TIMEOUT}).success(function (data){
            if (data.objects.length == 0){
                $scope.QRY_STATUS = "NO_RESULTS";
            }
            else if (data.objects[0] == "error") {
                $scope.QRY_STATUS = "QRY_ERROR";
            }
            else {
                $scope.QRY_STATUS = "HAVE_WEBPAGE_RESULTS";
            }

            app.records = data.objects;
                
            app.sites = [];
            seen_urls = [];
            already_seen = [];

            for (var i = 0; i < app.records.length; i++){
                var cur_site = app.records[i];

                //alert("cur_site --> " + JSON.stringify(cur_site));

                var to_add = {"url": cur_site.url,
                              "occur": cur_site.pageviews.length,
                              "resources": {}};
                
                for (var pv_ind = 0; pv_ind < app.records[i].pageviews.length; pv_ind++){
                    var cur_pageview = app.records[i].pageviews[pv_ind];
                    //alert("cur_pageview --> " + JSON.stringify(cur_pageview));
            
                    for (var script_ind = 0; script_ind < cur_pageview.resources.length; script_ind++){
                        var script_url = cur_pageview.resources[script_ind].url;
                        var script_hash = cur_pageview.resources[script_ind].hash;

                        if (!(script_url in to_add.resources)){
                            to_add.resources[script_url] = {};
                            to_add.resources[script_url].url = script_url; // might not be necessary
                            to_add.resources[script_url].hashes = {};
                            to_add.resources[script_url].occur = 0;
                        }
                        
                        if (!(script_hash in to_add.resources[script_url].hashes)){
                            to_add.resources[script_url].hashes[script_hash] = {};
                            to_add.resources[script_url].hashes[script_hash].hash = script_hash; // might not be necessary
                            to_add.resources[script_url].hashes[script_hash].occur = 0;
                        }
                        
                        to_add.resources[script_url].occur += 1;
                        to_add.resources[script_url].hashes[script_hash].occur += 1;
                    }
                }

                // convert hash occur values to percentages
                for (var script_url in to_add.resources){
                    for (var hash_val in to_add.resources[script_url].hashes){
                        to_add.resources[script_url].hashes[hash_val].occur *= (100.0 / to_add.resources[script_url].occur);
                    }
                    
                    to_add.resources[script_url].occur *= (100.0 / to_add.occur);
                }

                //alert(to_add);
                app.sites.push(to_add);
            }
            
        }).error(function(data){
            $scope.QRY_STATUS = "QRY_ERROR";
        });
    }

    setTimeout($scope.check_for_query_params, 50);
});


app.controller('ModalInstanceCtrl', function ($scope, $modalInstance, currentObj, resourceUrl, webpageUrl, openWebsite, openResource, openHash) {
  $scope.currentObj = currentObj;

  $scope.resourceUrl = resourceUrl;
  $scope.webpageUrl = webpageUrl;
 
  $scope.openObj = function(obj, type, webpageUrl, resourceUrl){
    if (type == "website") openWebsite(obj);
    else if (type == "resource") openResource(obj, webpageUrl);
    else if (type == "hash") openHash(obj, resourceUrl, webpageUrl);
  }

  $scope.ok = function () {
    $modalInstance.close();
  };
});
