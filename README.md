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

(Check back later for more information on how to use the Chrome extension. You can 
install it as [an unpacked extension](http://superuser.com/questions/247651/how-does-one-install-an-extension-for-chrome-browser-from-the-local-file-system)
at your own risk for now.)


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

Optionally, you can have the Chrome extension send the full content of the scripts you
download to the server too. This will be turned off by default in all released versions.

Here are some steps that have been made to make this process as trustworthy as possible:
 - The connection from you to the remote upload server will always be 
   [encrypted using SSL/TLS](https://www.ssllabs.com/ssltest/analyze.html?d=scriptobservatory.org). 
 - No IP addresses or User IDs are ever recorded in the database.
 - The source code for both the client and the server will always be available for you to 
   review. (See the 
   [chrome-extension/](https://github.com/andy11/ScriptObservatory/tree/master/chrome-extension) 
   and [backend/](https://github.com/andy11/ScriptObservatory/tree/master/backend) 
   directories to get started.)


Roadmap
-------

Milestone 4 (target date= 4/30):
 - Have time value be added server-side
 - Add tests for backend API & chrome extension code
 - Support (optionally) keeping content of HTML
 - Support iframes
 - Support YARA scanning full database archive + live alerting on new submissions
 - Make chrome extension check if a script already exists to avoid hammering POSTs to server

Milstone 5 (target date= 5/15):
 - Add button to chrome extension to toggle reporting on and off
 - Add button to chrome extension to view current page's analysis page
 - Allow blacklisting stats upload for website regexes in the chrome extension
 - Have chrome extension automatically report all errors while browsing sites
 - Improve visualizations for what scripts & versions of scripts have been included
 - Improve test cases 
 - Make robobrowser delete task only on success (or possibly add it back in on fail)

Longer-term:
 - Let users view scripts in extension and choose whether or not to allow them to run
 - Make sure there's no interference with other extensions / ad-blockers
 - Add interactive visualizations for collected data
 - Support flash objects
 - Allow users to import web traffic from PCAP


Contributing
------------

If you have ideas/comments/suggestions, please submit them as Issues or Pull Requests. Thanks!

