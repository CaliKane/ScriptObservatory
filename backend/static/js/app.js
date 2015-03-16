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

});

