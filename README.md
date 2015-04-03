ScriptObservatory
=================

The goal of the ScriptObservatory project is to extend the idea behind the 
[SSL Observatory](https://www.eff.org/observatory) by recording and 
information about the **_live content_** people are seeing on
the internet.

Initially, the only objects that will be analyzed are JavaScript files. 
Eventually, it might be extended to include other types of content like 
flash objects and iframes. 

The long-term goal of the [website](https://www.scriptobservatory.org)
is for it to be a place where anyone can analyze the record of 
what snippets of code people have been sent while on the internet. The 
long-term goal for the 
[Chrome extension](https://github.com/andy11/ScriptObservatory#usage)
is to crowdsource the data collection and to (optionally) act as a 
**_content-aware_** script blocker, letting you have finer control 
over what runs on your computer. 


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
you can set up a server of your own and configure the extension to send data there
instead.


Roadmap
-------

v0.2:
 - Set up / teardown the Xvfb display within the Python script 
 - Move to UI bootstrap (https://angular-ui.github.io/bootstrap/)
 - Add small menu for clicking on results within stats:
    - Site URL: 
        - search for this website here
        - scan this website again now
        - view on URLQuery
        - view on VirusTotal
        - builtwith.com
        - copy URL to clipboard
    - Script URL:
        - see all sites that have used this script
        - view current script content
        - view on VirusTotal
        - copy URL to clipboard
    - Script Hash:
        - see all sites that have used this version of this script
        - view archived script content (eventually)
        - view on VirusTotal
        - copy Hash to clipboard
 - Autoscan queried websites with no prior results
 - Add progress indicator when making queries on the website
 - Make queries link-able and have traditional URL paths

v0.3:
 - Add button to chrome extension to toggle reporting on and off
 - Allow blacklisting stats upload for websites in the chrome extension
 - Make Chrome extension public

v0.4:
 - Add tests for chrome extension code
 - Have robobrowser automatically report all errors while browsing sites
 - Build a VM-based solution to sandbox the robobrowser

Long-term:
 - Support iframes
 - Support flash objects
 - Add interactive visualizations for collected data
 - Make sure there's no interference with other extensions / ad-blockers
 - Rework database structure to scale better
 - Allow users to import web traffic from PCAP


Contributing
------------

If you have ideas/comments/suggestions, please submit them as Issues or Pull Requests. Thanks!

