/* DSM desktop integration (DSM 7.2+): opens SecDash in a native, resizable
   DSM window that hosts the dashboard page in an iframe. DSM loads this file
   into its own desktop, so it must only define these namespaced classes. */
Ext.namespace("SYNO.SDS.SecDash.Utils");

Ext.apply(SYNO.SDS.SecDash.Utils, function () {
    return {
        getMainHtml: function () {
            return '<iframe src="webman/3rdparty/SecDash/index.html?_ts=' + new Date().getTime() +
                '" title="SecDash" style="width: 100%; height: 100%; border: none; margin: 0"></iframe>';
        }
    };
}());

Ext.define("SYNO.SDS.SecDash.Application", {
    extend: "SYNO.SDS.AppInstance",
    appWindowName: "SYNO.SDS.SecDash.MainWindow",
    constructor: function () {
        this.callParent(arguments);
    }
});

Ext.define("SYNO.SDS.SecDash.MainWindow", {
    extend: "SYNO.SDS.AppWindow",
    constructor: function (a) {
        var me = SYNO.SDS.SecDash;
        this.appInstance = a.appInstance;
        me.MainWindow.superclass.constructor.call(this, Ext.apply({
            layout: "fit",
            resizable: true,
            maximizable: true,
            minimizable: true,
            width: 1180,
            height: 780,
            minWidth: 640,
            minHeight: 420,
            html: me.Utils.getMainHtml()
        }, a));
    },

    onOpen: function () {
        SYNO.SDS.SecDash.MainWindow.superclass.onOpen.apply(this, arguments);
        this.watchIframeClicks();
    },

    // Clicks inside the iframe never reach DSM's window manager, so clicking the
    // page wouldn't raise this window above others. Raise it ourselves, without
    // calling focus(), so a click into a text box keeps the caret there.
    watchIframeClicks: function (tries) {
        var win = this, iframe = this.body && this.body.dom && this.body.dom.querySelector("iframe");
        if (!iframe) {  // window body not rendered yet
            tries = tries || 0;
            if (tries < 20) {
                setTimeout(function () { win.watchIframeClicks(tries + 1); }, 250);
            }
            return;
        }
        if (iframe._sdWatched) {
            return;
        }
        iframe._sdWatched = true;
        var raise = function () {
            var mgr = win.manager;
            if (mgr && mgr.getActive && mgr.getActive() === win) {
                return;
            }
            if (mgr && mgr.bringToFront) {
                mgr.bringToFront(win);
            } else if (win.toFront) {
                win.toFront();
            }
        };
        var hook = function () {
            try {
                iframe.contentWindow.document.addEventListener("mousedown", raise, true);
                iframe.contentWindow.document.addEventListener("touchstart", raise, true);
            } catch (e) { /* not same-origin; nothing to do */ }
        };
        iframe.addEventListener("load", hook);
        hook();
    },

    onRequest: function (a) {
        SYNO.SDS.SecDash.MainWindow.superclass.onRequest.call(this, a);
    },

    onClose: function () {
        SYNO.SDS.SecDash.MainWindow.superclass.onClose.apply(this, arguments);
        this.doClose();
        return true;
    }
});
