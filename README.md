ScriptObservatory
=================

The goal of the ScriptObservatory project is to extend the idea behind the 
[SSL Observatory](https://www.eff.org/observatory) to include **_live content_**
from the internet.

Initially, the only objects that the ScriptObservatory will target for analysis 
will be files that Chrome classifies as "scripts" (like Javascript, for example).
If things go well, it may be extended to include additional types of resources.

Want to browse the data? [Start here](https://www.scriptobservatory.org).

Want to install the Chrome extension to add what you see to the observatory?
[Start here](https://github.com/andy11/ScriptObservatory#usage).


Usage
-----

(check back later)


How It Works
------------

The ScriptObservatory extension is notified every time your browser is about to
make a request for an object that Chrome classifies as a "script". ScriptObservatory
stops the browser from making the request and makes its own request instead.
Once it has received the content, it calculates a hash of the data it received and 
passes the object back to the browser to be used like normal.

This way of grabbing the content isn't ideal, but documentation of design decisions 
can be found in the source code itself (start with chrome-extension/background.js).

Periodically, the extension will upload the data it collects to a ScriptObservatory
server to be recorded. These four pieces of information are sent to the server:
 1. The full URL of the object
 2. The parent URL of the page that embeds the object
 3. The SHA-256 hash of the retrieved content
 4. The time that you viewed the object

In the future, ScriptObservatory might be extended to support uploading the content
of what you received in the event that there's a hash mismatch between what you saw
and what the server has on record for that URL. This will always be an optional 
feature and it will always be clearly visible in the settings panel.


Privacy
-------

With this extension installed, your browser will send the data described above to a 
remote server (https://www.scriptobservatory.org) at regular intervals.

The following steps have been taken to attempt to make the ScriptObservatory extension
as trustworthy as possible:
 - The connection from the Chrome extension to the remote server will always be encrypted 
   using SSL/TLS. (It will fail otherwise.)
 - No IP Addresses or any kind of "User ID" values will ever be recorded in the database or 
   saved in association with the uploaded data. This makes viewing the data on a "per-user"
   basis impossible.
 - The source code for both the client and the server will always be available for you to 
   review (see chrome-extension/ and backend/ directories to get started).

If you still don't feel comfortable having the extension upload your data to the centralized
server, you can set up your own, private version of the server and configure the extension 
to send data there instead.

I haven't decided yet, but at some point I may restrict access to the analysis & data 
to people who have the extension installed in their browser. Without people contributing 
their observations to the project, interesting data and analysis will never be possible.

Currently, it's not clear if the ScriptObservatory extension will interfere with 
the operation of other extensions like adblockers. You might find that your 
requests to Google Analytics & other trackers go through even though they would 
usually be blocked. I'll eventually try to address this.


Roadmap
-------

Near-term:
 - ~~Add support to track parent URL~~
 - Set up backend on https://scriptobservatory.org 
 - Set up a robobrowser to collect data from popular sites & look for bugs
 - Fix/finalize parent URL tracking setup
 - Support embedded script tags
 - Add filter to webpage to let users search by Parent URL, Script URL, and Hash values
 - Add filter to webpage to let users select data from specific date ranges
 - Add "by_script" view to webpage
 - Support batching uploads
 - Expand Privacy documentation
 - Update/clean README & all documentation

Long-term:
 - Expand to collect data on _all_ web objects?
 - Don't interfere with other extensions / ad-blockers
 - Add visualizations for server's data
 - Improve scalability of backend design


Contributing
------------

If you have ideas/comments/suggestions, go ahead and submit them as Issues or Pull Requests. Thanks!


