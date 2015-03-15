var app = angular.module("app", []);

BASE_URL = "127.0.0.1:8080";

app.controller("AppCtrl", function($http, $scope){
    var app = this;

    /*
       Auto-refreshers for updates every 10s
        this is hacky and should be changed, but it's good enough for now...
    */
    window.setInterval(function(){
        $http.get("/api/script").success(function (data){
            if (data.objects != app.scripts){
                app.scripts = data.objects;
            }
        });
    }, 10000);


    /*
        Main Script API
    */
    $http.get("/api/script").success(function (data){
        app.scripts = data.objects;
    });

    /* Manually adding URLs is disabled for now...
    app.addScript = function(url) {
        // if a script with this url exists, don't duplicate it:
        for (i=0; i < app.scripts.length; ++i){
            if (app.scripts[i].url == url) return;
        }

        // calculate hash value
        hash = "hash val";

        // make post request
        $http.post("/api/script", {"url":url, "sha256":hash})
            .success(function (data){
                app.scripts.push(data);
            });
    };
    */

    /* Manually deleting URLs is disabled for now...
    app.deleteScript = function(url){
        $http.delete("/api/script/" + url.id).success(function (response) {
            app.players.splice(app.scripts.indexOf(url), 1)
        })
    };
    */

});


