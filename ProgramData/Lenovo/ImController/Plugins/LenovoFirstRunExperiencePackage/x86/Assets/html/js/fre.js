var welcomePageName = 'WelcomePage';
var premiumCarePageName = 'PremiumCarePage';
var vantagePageName = 'VantagePage';
var dropboxPageName = 'DropBoxPage';
var appsforyouPageName = 'AppsForYouPage';
var migratePageName = 'MigratePage';
var lenovoidPageName = 'LenovoIDPage';
var alldonePageName = 'AllDonePage';
var closeAppPageName = 'closeApp';

var appName = 'LenovoWelcome';

var companionVersion = '4.27.32.0';

var navigateNext = 'next';
var navigateBack = 'back';

var lenovoIDInitialized = false;
var subscriptionInitialized = false;
var miniAnimationTimePassed = false;
var lenovoIDSigned = false;
var getEntitledStateDone = false;
var IsImcEntitled = false;
var IsSubsciptionEntitled = false;

var ADNotConfiged = 0;
var ADEnabled = 1;
var ADDisabled = 2;

var DropboxNotInstall = 0;
var DropboxDownloading = 1;
var DropboxInstalling = 2;
var DropboxRunning = 3;

// Define metric error code send from JS, which is starting from 101
const MetricsErrorCode = {
    BatteryGuageNotInstalled: 101,
    DropboxUnreachable: 102,
    DropboxSignupUnknownError: 103,
    DropboxSigninUnknownError: 104,
    SsoTimestampIncorrect: 105,
    SsoCommonInfo: 106,
    InternetNotFound: 107,
    OnlyRunLenovoDevice: 108,
    DownloadFailed: 109,
    InstallFailed: 110
}

var pageInfo = {
  currentPageIndex: 0,
  currentPageName: '',
  pageArray: [{
    name: welcomePageName,
    show: false
  },
  {
    name: premiumCarePageName,
    show: false
  },
  {
    name: vantagePageName,
    show: false
  },
  {
    name: appsforyouPageName,
    show: false
  },
  {
    name: dropboxPageName,
    show: false
  },
  {
    name: migratePageName,
    show: false
  },
  {
    name: lenovoidPageName,
    show: false
  },
  {
    name: alldonePageName,
    show: false
  }
  ]
};

function initializeAllDone() {
    //if we do not subscribe the entitled status(IsSubsciptionEntitled == false), then we don't need to see the 'getEntitledStateDone status
    return lenovoIDInitialized && subscriptionInitialized && miniAnimationTimePassed && (IsSubsciptionEntitled == false || getEntitledStateDone);
}

function isAllowedSelect(name, show) {
  if (!show) return false;

  if (name === dropboxPageName) {
    if (getDropBoxState() !== DropboxNotInstall) return false;
  }

  if (name === lenovoidPageName) {
    if (lenovoIDSigned) return false;
  }

  return true;
}

function checkInitialPageDueToLIDAndDropbox() {
  if (isAllowedSelect(pageInfo.currentPageName, pageInfo.pageArray[pageInfo.currentPageIndex].show)) return;

  for (var i = pageInfo.currentPageIndex + 1; i < pageInfo.pageArray.length; i++) {
    if (isAllowedSelect(pageInfo.pageArray[i].name, pageInfo.pageArray[i].show)) {
      saveCurrentInfo(i, pageInfo.pageArray[i].name);
      return;
    }
  }

  for (var j = pageInfo.currentPageIndex - 1; j >= 0; j--) {
    if (isAllowedSelect(pageInfo.pageArray[j].name, pageInfo.pageArray[j].show)) {
      saveCurrentInfo(j, pageInfo.pageArray[j].name);
      return;
    }
  }

  // there is no page could be shown
  saveCurrentInfo(0, '');
}

function pageNavigate(targetName, previousName, type) {
  var previousPage = '#' + previousName;
  var targetPage = '#' + targetName;
  if (type === navigateNext) {
    $(previousPage).removeClass('left-to-middle');
    $(previousPage).removeClass('right-to-middle');
    $(previousPage).removeClass('middle-to-left');
    $(previousPage).removeClass('middle-to-right');

    $(targetPage).removeClass('left-to-middle');
    $(targetPage).removeClass('right-to-middle');
    $(targetPage).removeClass('middle-to-left');
    $(targetPage).removeClass('middle-to-right');

    $(previousPage).addClass('middle-to-left');
    $(targetPage).addClass('right-to-middle');
  } else if (type === navigateBack) {
    $(previousPage).removeClass('left-to-middle');
    $(previousPage).removeClass('right-to-middle');
    $(previousPage).removeClass('middle-to-left');
    $(previousPage).removeClass('middle-to-right');

    $(targetPage).removeClass('left-to-middle');
    $(targetPage).removeClass('right-to-middle');
    $(targetPage).removeClass('middle-to-left');
    $(targetPage).removeClass('middle-to-right');

    $(previousPage).addClass('middle-to-right');
    $(targetPage).addClass('left-to-middle');
  }

  hidePageScrollBar(previousPage);
  showPageScrollBar(targetPage);

  logPageViewEvent(targetName);
  setCurrentPage(targetName);
}

function hasBackBtn() {
  if (pageInfo.currentPageIndex === 0) return false;
  for (var index = pageInfo.currentPageIndex - 1; index >= 0; index--) {
    if (pageInfo.pageArray[index].show === true) {
      return true;
    }
  }
  return false;
}

function hasNextBtn() {
  if (pageInfo.currentPageIndex + 1 >= pageInfo.pageArray.length) return false;
  for (var index = pageInfo.currentPageIndex + 1; index < pageInfo.pageArray.length; index++) {
    if (pageInfo.pageArray[index].show === true) {
      return true;
    }
  }
  return false;
}

function goBack(eventTriggeredPageName) {
  if (eventTriggeredPageName !== pageInfo.currentPageName) return;
  if (pageInfo.currentPageIndex === 0) return;

  for (var index = pageInfo.currentPageIndex - 1; index >= 0; index--) {
    if (isAllowedSelect(pageInfo.pageArray[index].name, pageInfo.pageArray[index].show)) {
      var previousIndex = pageInfo.currentPageIndex;
      pageInfo.currentPageIndex = index;
      pageInfo.currentPageName = pageInfo.pageArray[index].name;
      pageNavigate(pageInfo.currentPageName, pageInfo.pageArray[previousIndex].name, navigateBack);
      return;
    }
  }
}

function goNext(eventTriggeredPageName) {
  if (eventTriggeredPageName !== pageInfo.currentPageName) return;
  if (pageInfo.currentPageIndex + 1 >= pageInfo.pageArray.length) return;

  for (var index = pageInfo.currentPageIndex + 1; index < pageInfo.pageArray.length; index++) {
    if (isAllowedSelect(pageInfo.pageArray[index].name, pageInfo.pageArray[index].show)) {
      var previousIndex = pageInfo.currentPageIndex;
      pageInfo.currentPageIndex = index;
      pageInfo.currentPageName = pageInfo.pageArray[index].name;
      pageNavigate(pageInfo.currentPageName, pageInfo.pageArray[previousIndex].name, navigateNext);
      return;
    }
  }
}

function getXML(para) {
  subscriptionInitialized = true;
  initializePageInfo(JSON.parse(para.value));

  if (!initializeAllDone()) return;

  showInitiaPage();
  hideOpeningAnimation();
}

function initializePageInfo(data) {
  var showWarranty = getShowOrHideWarrantyCheckbox();
  if (showWarranty) {
    showWarrantyCheckbox();
  }
    
  var tempAppList = {};
  $.each(appList, function enumList(appId) {
     tempAppList['WelcomeApp.Features.AppsForYouPage.' + appId + '.Enable'] = true;
    });

  var showAmazon = true;
  var showWinzip = true;
  var showFacebook = true;
  var showDeezer = true;
  var showYoutube = true;
  var showKingSoft = true;
  var showCyberlink = true;
  var showAlexaForPC = true;
  $.each(data.AppSettingList, function enumList(index, item) {
    $.each(pageInfo.pageArray, function enumArray(arrIndex, page) {
      var attr = 'WelcomeApp.Features.' + page.name + '.Enable';
      if (item.Key === attr) {
        pageInfo.pageArray[arrIndex].show = item.Value === 'true';
        return false;
      }
      return true;
    });

    // var tempItem = tempAppList[item.Key];
    // if ( tempItem != null && item.Value === 'false') {
    //   $('#' + tempItem.appId).hide();
    // }

    if (item.Key === 'WelcomeApp.Features.AppsForYouPage.amazonAssistant.Enable' && item.Value === 'false') {
      showAmazon = false;
    }

    if (item.Key === 'WelcomeApp.Features.AppsForYouPage.winzip.Enable' && item.Value === 'false') {
      showWinzip = false;
    }

    //hide kingsoft by subscription file and show facebook instead
    if (item.Key === 'WelcomeApp.Features.AppsForYouPage.kingsoftWPSOffice.Enable' && item.Value === 'false') {
      showKingSoft = false;
    }

    if (item.Key === 'WelcomeApp.Features.AppsForYouPage.facebook.Enable' && item.Value === 'false') {
      showFacebook = false;
    }

    if (item.Key === 'WelcomeApp.Features.AppsForYouPage.deezer.Enable' && item.Value === 'false') {
      showDeezer = false;
    }

    if (item.Key === 'WelcomeApp.Features.AppsForYouPage.cyberlinkMediaPlayer.Enable' && item.Value === 'false') {
      showCyberlink = false;
    }

    if (item.Key === 'WelcomeApp.Features.AppsForYouPage.youTube.Enable' && item.Value === 'false') {
      showYoutube = false;
    }

    if (item.Key === 'WelcomeApp.Features.AppsForYouPage.alexaForPC.Enable' && item.Value === 'false') {
      showAlexaForPC = false;
    }

    if ((item.Key === 'WelcomeApp.Features.MigratePage.MigrateCheckbox.Enable') && (item.Value === 'true')) {
      showMigrateCheckbox();
    }

    if ((item.Key === 'WelcomeApp.ShowSoftwareEntitled') && (item.Value === 'true')) {
      IsSubsciptionEntitled = true;
    }
  });

  if (!showAmazon) {
    $('#app-amazonAssistant').remove();
  }

  if (!showWinzip) {
    $('#app-winzip').remove();
  }

  if (showKingSoft) {
    $('#app-facebook').remove();
} else {
    $('#app-kingsoftWPSOffice').remove();
  }

  if (!showFacebook) {
    $('#app-facebook').remove();
  }

  if (!showDeezer) {
    $('#app-deezer').remove();
  }

  if (!showCyberlink) {
    $('#app-cyberlinkMediaPlayer').remove();
  }

  if (!showYoutube) {
    $('#app-youTube').remove();
  }

  if (!showAlexaForPC) {
    $('#app-alexaForPC').remove();
  }
}

function saveCurrentInfo(index, name) {
  pageInfo.currentPageIndex = index;
  pageInfo.currentPageName = name;
}

function adjustADPolicy() {
  var ad = JSON.parse(getADPolicyState());

  ad.forEach(function (element) {
    var val = Number(element.Value);
    if (val === ADNotConfiged) return;

    if (val === ADDisabled) {
      pageInfo.pageArray.forEach(function (e) {
        if (element.PageName === e.name) {
          e.show = false;
        }
      });
    }

    if (val === ADEnabled) {
      pageInfo.pageArray.forEach(function (e) {
        if (element.PageName === e.name) {
          e.show = true;
        }
      });
    }
  });
}

function getInitialPage() {
  var pageName = getCurrentPage();

  if (pageName === '') {
    saveCurrentInfo(0, pageInfo.pageArray[0].name);
    return;
  }

  $.each(pageInfo.pageArray, function enumArray(arrIndex, page) {
    if (pageName === page.name) {
      saveCurrentInfo(arrIndex, page.name);
      return false;
    }
    return true;
  });

  if (pageInfo.currentPageName === '') {
    saveCurrentInfo(0, pageInfo.pageArray[0].name);
  }
}

function hidePageScrollBar(pageName) {
  $(pageName).css('overflow-y', 'hidden');
}

function showPageScrollBar(pageName) {
  $(pageName).css('overflow-y', 'auto');
  $(pageName).scrollTop(0);
}

function showInitiaPage() {
  UpdateWelcomePageSteps();
  UpdateEntitledUI();
  adjustADPolicy();
  getInitialPage();
  checkInitialPageDueToLIDAndDropbox();
  if (pageInfo.currentPageName === '') {
    logEvent({
      metricsType: 'LogError',
      metricsName: rs.msg['sso-common-info'],
      metricsValue: MetricsErrorCode.SsoCommonInfo
    });
    showGeneralError(rs.msg['sso-common-info'], closeFreApp);
    return;
  }

  var name = pageInfo.currentPageName;
  $('#' + name).css('visibility', 'visible');
  showPageScrollBar('#' + name);
  logPageViewEvent(name);
  setCurrentPage(name);
}

function loadStrings() {
  var resources = loadResource();
  var result = {};
  $.each(JSON.parse(resources), function parseResource(section, resource) {
    result[section] = {};
    if (section === 'title' || section === 'placeholder') {
      $.each(resource, function parse(key, value) {
        result[section][key] = value;
        $('[data-i18n-' + section + '=' + key + ']').attr(section, value);
      });
    } else {
      $.each(resource, function parse(key, value) {
        result[section][key] = value;
        $('[data-i18n-' + section + '=' + key + ']').html(value);
      });
    }
  });
  return result;
}

function getElementValue(element) {
  if (element.prop('nodeName').toLowerCase() !== 'input') return '';

  switch (element.prop('type').toLowerCase()) {
  case 'checkbox':
    return element.is(':checked') ? 'on' : 'off';
  default:
    return '';
  }
}

function logEventForItemClick(objThis) {
    var data = jQuery(objThis).data();
    if (jQuery(objThis).attr('data-metrics-value') === '') {
        data.metricsValue = getElementValue($(objThis));
    }
    if (data !== null) {
        logEvent(data);
    }
}

function registerMetricEvents() {
  jQuery("[data-metrics-type='ItemClick']").on('click', function itemClick() {
    logEventForItemClick($(this));
  });

  jQuery('[data-metrics-type="ItemView"]').each(function itemView() {
    var data = jQuery(this).data();
    if (data !== null) {
      logEvent(data);
    }
  });

  jQuery('[data-metrics-type="PageView"]').each(function pageView() {
    var data = jQuery(this).data();
    if (data !== null) {
      logEvent(data);
    }
  });
}

function sendDropBoxPageViewEvent() {
  if ($('.sign-in-view').css('display') === 'block') {
    logEvent({
      metricsType: 'PageView',
      metricsName: 'Features.Dropbox.SignInPage',
      metricsParent: ''
    });
  }

  if ($('.sign-up-view').css('display') === 'block') {
    logEvent({
      metricsType: 'PageView',
      metricsName: 'Features.Dropbox.SignUpPage',
      metricsParent: ''
    });
  }
}

function logPageViewEvent(currentSection) {
  var metricsName = '';
  var entitled = null;

  switch (currentSection) {
  case welcomePageName:
    metricsName = 'Features.WelcomePage';
    break;
  case premiumCarePageName:
    metricsName = 'Features.PremiumCarePage';
    break;
  case vantagePageName:
    metricsName = 'Features.Tangram';
    break;
  case dropboxPageName:
    metricsName = 'Features.Dropbox';
    sendDropBoxPageViewEvent();
    break;
  case appsforyouPageName:
    metricsName = 'Features.AppsForYou';
    break;
  case migratePageName:
    metricsName = 'Features.DataMigration';
    break;
  case lenovoidPageName:
    metricsName = 'Features.LenovoID.SignInPage';
    break;
  case closeAppPageName:
    metricsName = 'Features.ClosePage';
    break;
  case alldonePageName:
    if (IsImcEntitled && IsSubsciptionEntitled) {
      entitled = 'entitled'
    };
    metricsName = 'Features.AllDonePage';
    break;
  default:
    break;
  }

  if (currentSection !== dropboxPageName) {
    logEvent({
      metricsType: 'PageView',
      metricsName: metricsName,
      metricsParent: '',
      context: entitled
    });
  }
}
