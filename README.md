ScriptObservatory
=================

The goal of the ScriptObservatory project is to extend the idea behind the 
[SSL Observatory](https://www.eff.org/observatory) to include **_live content_**
from the internet.

Initially, the only objects that the ScriptObservatory will target for analysis 
will be files that Chrome classifies as "scripts" (for ex: Javascript). If things 
go well, it may be extended to include additional types of objects pulled down 
off the Internet.

_Want to browse the data?_ Start [here](https://www.scriptobservatory.org).

_Want to install the Chrome extension to add what you see to the observatory?_
Start [here](https://github.com/andy11/ScriptObservatory#usage).


Usage
-----

(check back later)


How It Works
------------

The ScriptObservatory extension is notified every time your browser is about to
make a request for an object that Chrome classifies as a "script". ScriptObservatory
will stop the browser from making the request and make its own request instead.
Once it receives the content, it calculates a hash of the data it received and 
passes the object back to the browser to be used as it normally would.

This is not ideal, but documentation of specific design decisions can be found 
in the source code itself (start with chrome-extension/background.js).

Periodically, the extension will upload the data it collects to a server to be recorded. 
The information it collects includes:
 1. The full URL of the object
 2. The parent URL of the page that embeds the object
 3. The SHA-256 hash of the retrieved content
 4. The time that you viewed the object

In the future, ScriptObservatory might be extended to support uploading the content
received by the extension in the event that there's a hash mismatch between what you saw
and what the server has on record for that URL.

At this point, ScriptObservatory doesn't play well with other extensions like adblockers.
You might find that your requests to Google Analytics & other trackers will go through
even though they would usually be blocked. I'll eventually try to address this, but it
isn't the highest priority at the moment.


Privacy
-------

With this extension installed, your browser will send the data described above to a 
remote server. If you don't feel comfortable with this, you can set it up to point
to your own server instead.


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


