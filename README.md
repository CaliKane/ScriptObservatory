ScriptObservatory
=================

The goal of the ScriptObservatory project is to extend the idea behind the 
[SSL Observatory](https://www.eff.org/observatory) to include recording and 
organizing **_live content_** from the internet as well as SSL certificates.

Initially, the only objects that the ScriptObservatory extension will target 
for analysis will be files that Chrome classifies as "scripts" (like 
Javascript, for example). It may eventually include additional types of 
resources as well.

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
Documentation of design decisions can be found directly in the source code (start 
with [chrome-extension/background.js](https://github.com/andy11/ScriptObservatory/blob/master/chrome-extension/src/background.js)).

Periodically, the extension will upload the data it collects to a ScriptObservatory
server to be recorded. These four pieces of information are sent to the server:
 1. The full URL of the requested script
 2. The full URL of the parent webpage where the script was included
 3. The SHA-256 hash of the script's content
 4. The time that you viewed the object


Privacy
-------

With the ScriptObservatory Chrome extension installed, your browser will send the
data described above to a remote server at regular intervals.

The following steps have been taken to make the process as trustworthy as possible:
 - The connection from you to the remote server will always be 
   [encrypted using SSL/TLS](https://www.ssllabs.com/ssltest/analyze.html?d=scriptobservatory.org). 
 - No IP addresses or any kind of "User ID" values will ever be recorded in the database or 
   logged on the server. This makes viewing the data on a "per-user" basis impossible.
 - The source code for both the client and the server will always be available for you to 
   review (see the 
   [chrome-extension/](https://github.com/andy11/ScriptObservatory/tree/master/chrome-extension) 
   and [backend/](https://github.com/andy11/ScriptObservatory/tree/master/backend) 
   directories to get started).

If you still don't feel comfortable having the extension upload your data to the centralized
server, you can set up your own, private version of the server and configure the extension 
to send data there instead.


Roadmap
-------

Near-term:
 - ~~Add support to track parent URL~~
 - ~~Set up backend on https://scriptobservatory.org~~
 - ~~Set up a robobrowser to collect data from popular sites~~
 - ~~Fix/finalize parent URL tracking setup~~
 - ~~Add filter to webpage to let users search by Parent URL, Script URL, and Hash values~~
 - ~~Support batching uploads~~
 - ~~Show total size of database on homepage~~
 - ~~Debug issue seen with robobrowser on JS-heavy websites~~
 - ~~Debug issue with non-ASCII encoded scripts~~ 
 - Add tests for chrome extension code
 - Give some kind of notification about progress if a query takes a long time
 - Support inline script tags
 - Allow users to submit sites to be robobrowsed (handle automatically when a new site is queried)
 - Allow users to click a "rescan" button when displaying current results
 - Add button to chrome extension to toggle reporting on and off
 - ~~Add way to search & view by script (by url & hash)~~
 - ~~Allow users to query from within a specific date range~~
 - Support flash objects
 - Show total size of database in github readme
 - Have robobrowser automatically report all errors while browsing sites

Long-term ideas:
 - Rework database structure to scale better
 - Expand to collect data on _all_ web objects?
 - Make sure there's no interference with other extensions / ad-blockers
 - Integrate with VirusTotal & other URL-scanning websites
 - Allow users to import web traffic from PCAP
 - Add interactive visualizations for collected data


Contributing
------------

If you have ideas/comments/suggestions, go ahead and submit them as Issues or Pull Requests. 


