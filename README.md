ScriptObservatory
=================

The goal of the ScriptObservatory project is to extend the idea behind the 
[SSL Observatory](https://www.eff.org/observatory) by recording and 
organizing information about the **_live content_** people are seeing on
the internet.

Initially, the only objects that the ScriptObservatory extension will target 
for analysis will be JavaScript files. Eventually, this may be extended to 
analyze other content like flash objects and iframes.

Want to browse the data? [Click here](https://www.scriptobservatory.org)

Want to install the Chrome extension? 
[Click here](https://github.com/andy11/ScriptObservatory#usage)


Usage
-----

(check back later)


How It Works
------------

The ScriptObservatory Chrome extension is notified every time your browser is 
about to make a request for an object that Chrome classifies as a "script". 
The extension stops the browser from making the request and makes its own request
instead. Once it receives the content, it calculates a hash of the data and 
passes the object back to the browser.

This way of grabbing the content isn't ideal and will hopefully be improved soon.
Documentation of design decisions can be found directly in the source code. 
([chrome-extension/extension.js](https://github.com/andy11/ScriptObservatory/blob/master/chrome-extension/extension.js)
would be a good place to start.)


Privacy
-------

With the ScriptObservatory Chrome extension installed, your browser will send these
four pieces of information to a remote server at regular intervals:
 1. The full URL of the script you downloaded
 2. The full URL of the parent webpage where the script was included
 3. The SHA-256 hash of the script's content
 4. The time you made this observation

Here are some steps that have been made to make this process as trustworthy as possible:
 - The connection from you to the remote upload server will always be 
   [encrypted using SSL/TLS](https://www.ssllabs.com/ssltest/analyze.html?d=scriptobservatory.org). 
 - No IP addresses or User IDs are ever recorded in the database or logged on the server.
 - The source code for both the client and the server will always be available for you to 
   review. (See the 
   [chrome-extension/](https://github.com/andy11/ScriptObservatory/tree/master/chrome-extension) 
   and [backend/](https://github.com/andy11/ScriptObservatory/tree/master/backend) 
   directories to get started.)

If you still don't feel comfortable having the extension upload data to the server, 
you can set up your own version and configure the extension to send data there instead.


Roadmap
-------

Near-term:
 - Add tests for chrome extension code
 - Make queries link-able and have traditional URL paths
 - Add progress indicator when making a query on the website
 - Create a web API to control the robobrowser
 - Allow users to click a "scan" button when displaying results
 - Autoscan queried websites with no prior results
 - Add button to chrome extension to toggle reporting on and off
 - Have robobrowser automatically report all errors while browsing sites

Long-term ideas:
 - Support inline script tags
 - Support flash objects
 - Integrate with VirusTotal & other URL-scanning websites
 - Add interactive visualizations for collected data
 - Make sure there's no interference with other extensions / ad-blockers
 - Rework database structure to scale better
 - Allow users to import web traffic from PCAP


Contributing
------------

If you have ideas/comments/suggestions, please submit them as Issues or Pull Requests. Thanks!

