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
