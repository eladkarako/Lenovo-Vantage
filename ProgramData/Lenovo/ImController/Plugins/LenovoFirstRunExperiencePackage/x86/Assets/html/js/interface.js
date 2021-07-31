function callClientFunctionInterface(paraData) {
  return window.external.callCSharpFromJs(JSON.stringify(paraData));
}

function callJsFromCSharp(json) {
  var parameter = JSON.parse(json);
  var func = window[parameter.callback];
  return func(parameter);
}

function notifyUIFromCSharp(json) {
  var parameter = JSON.parse(json);
  var func = window[parameter.callback];
  return func(parameter);
}

function FrontEndEventHandler(param) {
  var func = window[param.evt];
  return func(param);
}

function getNetworkState() {
  var state = getControlOptions(appName, 'NetworkDisconnect');
  return state.toLowerCase() === 'true' ? true : false;
}

/* js send request to client side */
function closeFreApp() {
  var paraData = {
    name: 'CloseApp',
    type: 'Async',
    operation: 'Do'
  };

  callClientFunctionInterface(paraData);
}

function uninstallApp() {
    var paraData = {
        name: 'UninstallApp',
        type: 'Async',
        operation: 'Do'
    };

    callClientFunctionInterface(paraData);
}

function premiumCareBuyNow(func) {
  var paraData = {
    name: 'DoAsync',
    type: 'Async',
    operation: 'Do',
    parameters: {
      paramUI: {
        page: premiumCarePageName,
        callback: func
      }
    }
  };

  callClientFunctionInterface(paraData);
}

function sendLenovoIdCommand(func) {
  var paraData = {
    name: 'DoAsync',
    type: 'Async',
    operation: 'Do',
    parameters: {
      paramUI: {
        page: lenovoidPageName,
        callback: func
      }
    }
  };

  callClientFunctionInterface(paraData);
}

function getSoftwareEntitledState(func) {
  var paraData = {
    name: 'DoAsync',
    type: 'Async',
    operation: 'Do',
    parameters: {
      paramUI: {
        page: alldonePageName,
        callback: func
      }
    }
  };

  callClientFunctionInterface(paraData);
}

function addAppToStartMenu() {
  var paraData = {
    name: 'AddAppToStartMenu',
    type: 'Sync',
    operation: 'Do'
  };

  callClientFunctionInterface(paraData);
}

function cancelMigration() {
  cancelDownloadAndInstall(migratePageName);
}

function cancelDropBox() {
  cancelDownloadAndInstall(dropboxPageName);
}

function cancelDownloadAndInstall(name) {
  var paraData = {
    name: 'CancelOperation',
    type: 'Async',
    operation: 'Do',
    parameters: {
      paramLogic: {
        page: name
      }
    }
  };

  callClientFunctionInterface(paraData);
}

function getDropBoxState() {
  var paraData = {
    name: 'GetDropBoxInstallStatus',
    type: 'Sync',
    operation: 'Get'
  };

  var ret = callClientFunctionInterface(paraData);
  return Number(ret);
}

function getShowOrHideWarrantyCheckbox() {
  var paraData = {
    name: 'GetShowOrHideWarrantyCheckbox',
    type: 'Sync',
    operation: 'Get'
  };

  var ret = callClientFunctionInterface(paraData);
  return ret.toLowerCase() === 'true' ? true : false;
}

function getCompanionVersion() {
  var paraData = {
    name: 'GetCompanionVersion',
    type: 'Sync',
    operation: 'Get'
  };

  var ret = callClientFunctionInterface(paraData);
  return ret.toLowerCase();
}

function getADPolicyState() {
  var paraData = {
    name: 'GetADPolicyValues',
    type: 'Sync',
    operation: 'Get'
  };

  return callClientFunctionInterface(paraData);
}

function downloadAndInstall(name, appid, tk, func) {
  var paraData = {
    name: 'DownloadAndInstall',
    type: 'Async',
    operation: 'Download',
    parameters: {
      paramUI: {
        page: name,
        callback: func,
        value: appid,
        token: tk
      }
    }
  };

  callClientFunctionInterface(paraData);
}

function navigate(type, value) {
  var paraData = {
    name: 'Navigate',
    type: 'Async',
    operation: 'Do',
    parameters: {
      paramLogic: {
        type: type,
        value: value
      }
    }
  };

  callClientFunctionInterface(paraData);
}

function openHtmlWithDefaultBrowser(url) {
  navigate('html', url);
}

function openUWP(portocol) {
  navigate('uri', portocol);
}

function openDesktop(name) {
  navigate('exe', name);
}

function getDeviceInfo(func) {
  var paraData = {
    name: 'GetModelName', // client need
    type: 'Async', // client need
    operation: 'Get',
    parameters: {
      paramUI: {
        page: welcomePageName,
        name: 'LabelModelName',
        callback: func,
        value: ''
      }
    }
  };

  callClientFunctionInterface(paraData);
}

function setCurrentPage(name) {
  var paraData = {
    name: 'SetCurrentPage',
    type: 'Sync',
    operation: 'Set',
    parameters: {
      paramUI: {
        page: name
      }
    }
  };

  return callClientFunctionInterface(paraData);
}

function getMetricOptions() {
  return getControlOptions(welcomePageName, 'MetricOpt');
}

function setMetricOptions(val) {
  setControlOptions(welcomePageName, 'MetricOpt', String(val));
}

function getToolbarOptions() {
  return getControlOptions(vantagePageName, 'VantageToolbar');
}

function setToolbarOptions(val) {
  setControlOptions(vantagePageName, 'VantageToolbar', String(val));
}

function getWarrantyOptions() {
  return getControlOptions(vantagePageName, 'VantageWarranty');
}

function setWarrantyOptions(val) {
  var obj = { check: val, warranty: rs.vantage['warranty-shortcut-text'], support: rs.vantage['support-shortcut-text'] };
  var value = JSON.stringify(obj);
  setControlOptions(vantagePageName, 'VantageWarranty', String(value));
}

function getWelcomeToolbarOptions() {
  return getControlOptions(welcomePageName, 'WelcomeVantageToolbar');
}

function setWelcomeToolbarOptions(val) {
  setControlOptions(welcomePageName, 'WelcomeVantageToolbar', String(val));
}

function getWelcomeWarrantyOptions() {
  return getControlOptions(welcomePageName, 'WelcomeVantageWarranty');
}

function setWelcomeWarrantyOptions(val) {
  var obj = { check: val, warranty: rs.vantage['warranty-shortcut-text'], support: rs.vantage['support-shortcut-text'] };
  var value = JSON.stringify(obj);
  setControlOptions(welcomePageName, 'WelcomeVantageWarranty', String(value));
}

function getShortcutOptions() {
  return getControlOptions(migratePageName, 'MigrationShortcut');
}

function setShortcutOptions(val) {
  setControlOptions(migratePageName, 'MigrationShortcut', String(val));
}

function getDropboxOptions() {
    return getControlOptions(dropboxPageName, 'DropboxAgreeTerm');
}

function getCurrentPage() {
  var paraData = {
    name: 'GetCurrentPage',
    type: 'Sync',
    operation: 'Get'
  };

  return callClientFunctionInterface(paraData);
}

function getSubscriptionXML(func) {
  var paraData = {
    name: 'GetXML',
    type: 'Async',
    operation: 'Get',
    parameters: {
      paramLogic: {
        callback: func,
        value: 'Subscription.xml'
      }
    }
  };

  callClientFunctionInterface(paraData);
}

function loadResource() {
  var paraData = {
    name: 'GetJson',
    type: 'Sync',
    operation: 'Get',
    value: 'en.json'
  };

  return callClientFunctionInterface(paraData);
}

function addVantageToToolbar(val, func) {
  var paraData = {
    name: 'AddVantageToolbar',
    type: 'Async',
    operation: 'Do',
    parameters: {
      paramUI: {
        page: vantagePageName,
        callback: func,
        value: val
      }
    }
  };

  return callClientFunctionInterface(paraData);
}

function isNetworkConnected() {
  var ret = getControlOptions(appName, 'NetworkDisconnect');
  return ret.toLowerCase() === 'true' ? true : false;
}

function isLenovoDevice() {
  var ret = getControlOptions(appName, 'OnlyRunOnLenovoDevice');
  return ret.toLowerCase() === 'true' ? true : false;
}

function createWebLink(applist) {
  var paraData = {
    name: 'CreateWebLinkShortcut',
    type: 'Async',
    operation: 'Do',
    parameters: {
      paramUI: {
        page: appsforyouPageName,
        value: applist
      }
    }
  };

  callClientFunctionInterface(paraData);
}

function getControlOptions(page, name) {
  var paraData = {
    name: 'GetControlOptions',
    type: 'Sync',
    operation: 'Get',
    parameters: {
      paramUI: {
        page: page,
        id: name
      }
    }
  };

  return callClientFunctionInterface(paraData);
}

function setControlOptions(page, name, val) {
  var paraData = {
    name: 'SetControlOptions',
    type: 'Async',
    operation: 'Set',
    parameters: {
      paramUI: {
        page: page,
        id: name,
        value: val
      }
    }
  };

  return callClientFunctionInterface(paraData);
}

function getControlKey() {
  var paraData = {
    name: 'GetControlValue',
    type: 'Sync',
    operation: 'Get',
    parameters: {
      paramUI: {
        page: 'DropBoxPage',
          value: 'jtIdmR/T/Ocw5ZZPf6yGZ/SS1Wvq2J4HL0ECbL3azpU='
      }
    }
  };

  return callClientFunctionInterface(paraData);
}

function getTotalPagesToShow() {
  let totalPages = 0;
  for (var index = 0; index < pageInfo.pageArray.length; index++) {
    if (pageInfo.pageArray[index].show === true) {
      totalPages++;
    }
  }
  return totalPages;
}

function logEvent(data) {
  try {
    var paraData = {
      name: 'SendMetric',
      type: 'Async',
      operation: 'Send',
      parameters: {
        paramLogic: {
          page: data.metricsParent,
          name: data.metricsName,
          type: data.metricsType,
          value: data.metricsValue,
          context: data.context
        }
      }
    };
    callClientFunctionInterface(paraData);
  } catch (err) {
    // log if need
  }
}

/* js recieve command from client side */

function NetworkDisconnect(e) {
  if (pageInfo.currentPageName === migratePageName) {
    cancelMigration();
    recoveryMigratePage();
    showNoInternetError();
    return;
  }

  showNoInternetError();
}

function BatteryGaugeNotInstalled(e) {
  showGeneralError(rs.msg['battery-guage-not-installed']);
  logEvent({
    metricsType: 'LogError',
    metricsName: rs.msg['battery-guage-not-installed'],
    metricsValue: MetricsErrorCode.BatteryGuageNotInstalled
  });
}

function ResumeFREHint(e) {
  if (pageInfo.currentPageName === alldonePageName || $('#closeApp').css('visibility') === 'visible') {
    return true; // true means the client will kill the fre process
  }

  if (isPopupShow()) return false;

  var backPage = '#' + pageInfo.currentPageName;

  $('#closeApp').css('visibility', 'visible');
  showPageScrollBar('#closeApp');
  $(backPage).removeClass('left-to-middle').removeClass('right-to-middle').css('visibility', 'hidden');
  hidePageScrollBar(backPage);
  logPageViewEvent(closeAppPageName);

  return false; // false means the client will do nothing
}
