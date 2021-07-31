var noInternetError = 0;
var generalError = 1;
var downloadDialog = 2;
var dToken;
var miniAnimationSeconds = 3;
var initializeTimeoutSeconds = 30;
var appName = 'Lenovo Welcome';
var dropboxDefaultEmail = 'none';

var WebLinkType = 0;
var ExecuteFileType = 1;

var dropboxGuid = 'D6580FA3-7655-45DD-BF50-8A691B89D836';
var migrateGuid = 'FCF9F618-10F4-4230-99DD-F9B1CCB316AF';

//tabIndex indicating the display order
var appList = {
  amazonAssistant: {
    guid: 'BE7237D9-4AB0-46A4-A522-6E022390FAB5',
      type: WebLinkType,
      tabIndex: 2,
      tag: 'amazon',
      metrics: 'Features.AppsForYou.AmazonButton',
      name:'Amazon Assistant'
  },
  winzip: {
    guid: '98DC09E7-4778-4319-B979-E080C2791D3F',
    type: ExecuteFileType,
    tabIndex: 3,
    tag: 'winzip',
    metrics: 'Features.AppsForYou.WinZipButton',
    name: 'WinZip'
  },
  facebook: {
    guid: 'AE3DAE2F-EB7E-4540-A0F4-7B967BE9A281',
    type: WebLinkType,
    tabIndex: 4,
    tag: 'facebook',
    metrics: 'Features.AppsForYou.FacebookButton',
    name: 'Facebook'
  },
  kingsoftWPSOffice: {
    guid: '05973120-4361-4B5E-AC4B-BF2D67A711E3',
    type: ExecuteFileType,
    tabIndex: 4,
    tag: 'kingsoft',
    metrics: 'Features.AppsForYou.KingsoftButton',
    name: 'WPS Office',
    defaultTip: 'WPS Office by Kingsoft'
  },
  deezer: {
    guid: 'E2C055AB-FC0E-441C-A6E9-81465C187F12',
    type: WebLinkType,
    tabIndex: 5,
    tag: 'deezer',
    metrics: 'Features.AppsForYou.DeezerButton',
    name: 'Deezer'
  },
  
  // cyberlinkPhotoDirector: {
  //   guid: '54A6EC9C-B4A1-4053-82BC-F195FC0DC8EA',
  //   type: ExecuteFileType
  // },
  //cyberlinkPowerDVD: {
  //  guid: '8E960D4B-31A4-41EE-8CCD-7A05EE108018',
  //  type: ExecuteFileType,
  //  tabIndex: 6,
  //  tag: 'cyberlink',
  //  metrics: 'Features.AppsForYou.CyberlinkButton',
  //  name: 'CyberLink Power DVD',
  //  defaultTip: 'CyberLink Power DVD'
  //},
  
  cyberlinkMediaPlayer: {
      guid: 'EEA35B08-1ECC-4CB3-BAFB-CE2F9D6D617B',
      type: ExecuteFileType,
      tabIndex: 6,
      tag: 'cyberlink',
      metrics: 'Features.AppsForYou.CyberlinkButton',
      name: 'CyberLink Media Player',
      defaultTip: 'Media Player Plus by CyberLink'
  },
  
  // nitroPdf: {
  //   guid: '373D5B2D-715B-40A2-8F20-057891D8B975',
  //   type: ExecuteFileType,
  //   tabIndex: 7,
  //   tag: 'nitroPdf',
  //   metrics: 'Features.AppsForYou.NitroProButton',
  //   id: 'nitroPdf'
  // },
  youTube: {
    guid: 'DEAD1C72-6025-41C7-9E0F-6087772D80F9',
    type: WebLinkType,
    tabIndex: 7,
    tag: 'youTube',
    metrics: 'Features.AppsForYou.YoutubeButton',
    name: 'YouTube',
    defaultTip: 'YouTube'
  },

  alexaForPC: {
    guid: 'AAA2AB6D-4A4D-4A4B-A0F5-8B4A89555CE9',
    type: WebLinkType,
    tabIndex: 8,
    tag: 'alexaForPC',
    metrics: 'Features.AppsForYou.AlexaForPCButton',
    name: 'Alexa for PC',
    defaultTip: 'Alexa for PC'
  }
};

function updateModelName(para) {
  $('#model-name').html(para.value);
}

function downloadAndInstallMigration() {
  $('.page-migrate .wel-back').hide();
  $('.page-migrate .go-next').hide();
  $('.download-line, .download-line-bg').show();
  $('#migrate-download').addClass('disable').attr('disabled', 'disabled');
  $('.migration-mask').show();
  setTabIndex(TabIndexDisabled);
  downloadAndInstall(migratePageName, migrateGuid, '', 'updateProgressBar');
}

function updateProgressBar(para) {
  if (pageInfo.currentPageName !== migratePageName) return;
  var progress = para.value + '%';
  if (para.status === 'downloading' || para.status === 'installing') {
    $('.download-line').css('width', progress);
  } else if (para.status === 'downloadSuccess') {
    $('.download-line').css('width', 100);
    recoveryMigratePage();
    setTabIndex(TabIndexEnabled);
    goNext(migratePageName);
  } else if (para.status === 'fail') {
    if (para.value === 'download') {
      logEvent({
        metricsType: 'LogError',
        metricsName: rs.msg['download-failed'],
        metricsValue: MetricsErrorCode.DownloadFailed
      });
      showGeneralError(rs.msg['download-failed']);
      recoveryMigratePage();
    } else if (para.value === 'install') {
      logEvent({
        metricsType: 'LogError',
        metricsName: rs.msg['install-failed'],
        metricsValue: MetricsErrorCode.InstallFailed
      });
      showGeneralError(rs.msg['install-failed']);
      recoveryMigratePage();
    }
  }
}

function recoveryMigratePage() {
  $('.migration-mask').hide();
  $('#migrate-download').removeClass('disable').removeAttr('disabled');
  $('.download-line').css('width', 0);
  $('.download-line, .download-line-bg').hide();
  $('.page-migrate .wel-back').show();
  $('.page-migrate .go-next').show();
}

function loginLenovoID() {
  showDialog();
  showLenovoId();
}

function showLenovoId() {
  sendLenovoIdCommand('LenovoIDStatus');
}

function getLIDStatus() {
  sendLenovoIdCommand('GetLenovoIDStatus');
}

function GetLenovoIDStatus(param) {
  lenovoIDInitialized = true;
  if (param.status === 'alreadySignedIn') {
    lenovoIDSigned = true;
    $('#su-email, #si-email').val(param.value);
    dropboxDefaultEmail = param.value;
  }

  if (initializeAllDone()) {
    showInitiaPage();
    hideOpeningAnimation();
  }
}

function SoftwareEntitled(para) {
  IsImcEntitled = para.status.toLowerCase() === 'true';
  getEntitledStateDone = true;
  if (!initializeAllDone()) return;

  showInitiaPage();
  hideOpeningAnimation();
}

function UpdateWelcomePageSteps() {
  let totalPages = getTotalPagesToShow();
  let textGoSetUp = rs.welcome['go-set-up'];
  textGoSetUp = textGoSetUp.replace('{0}', totalPages)
  $('#welcome-go-set-up').text(textGoSetUp);
}

function UpdateEntitledUI() {
    if (IsSubsciptionEntitled && IsImcEntitled) {
        $('[data-allDone-tangram="off"]').css('display', 'block');
    } else {
        $('[data-allDone-tangram="on"]').css('display', 'block');
    }
}

function LenovoIDStatus(para) {
  hideDialog();
  if (pageInfo.currentPageName !== lenovoidPageName) return;

  if (para.status === 'success' || para.status === 'alreadySignedIn') {
    // lenovoIDSigned = true;
    goNext(lenovoidPageName);
  } else if (para.status === 'userCancel') {
    // do nothing
  } else if (para.status === 'failed') {
    if (para.value === 'SSO_ErrorType_Common_Info') {
      showGeneralError(rs.msg['sso-common-info']);
    } else if (para.value === 'SSO_ErrorType_TimeStampIncorrect') {
      logEvent({
        metricsType: 'LogError',
        metricsName: rs.msg['sso-timestamp-incorrect'],
        metricsValue: MetricsErrorCode.SsoTimestampIncorrect
      });
      showGeneralError(rs.msg['sso-timestamp-incorrect']);
    }
  }
}

function initializeWelcomePage() {
  var metric = getMetricOptions();
  var val = metric.toLowerCase() === 'true' ? true : false;
  $('#metric').prop('checked', val);
  metric = getWelcomeToolbarOptions();
  val = metric.toLowerCase() === 'true' ? true : false;
  $('#welcome-toolbar-option').prop('checked', val);
  metric = getWelcomeWarrantyOptions();
  val = metric.toLowerCase() === 'true' ? true : false;
  $('#welcome-warranty-option').prop('checked', val);
}

function settingMetrics() {
  setMetricOptions($('#metric').is(':checked'));
}

function initializePremiumCarePage() {

}

$('#premium-care-explore-options').on('click', function () {
  premiumCareBuyNow('PremiumCareBuyNow');
  goNext(premiumCarePageName);
  return false;
});

function initializeVantagePage() {
  var metric = getToolbarOptions();
  var val = metric.toLowerCase() === 'true' ? true : false;
  $('#toolbar-option').prop('checked', val);
  metric = getWarrantyOptions();
  val = metric.toLowerCase() === 'true' ? true : false;
  $('#warranty-option').prop('checked', val);
}

function showWarrantyCheckbox() {
  $('.page-vantage .p-checkbox:nth-last-of-type(1)').show();
  $('.page-welcome .p-checkbox:nth-last-of-type(1)').show();
}

$.fn.extend({
  // copy ellipsis text to title
  textCopyToTitle: function () {
    $(this).attr('title', $(this).text());
  },
  // input max length
  inputMaxLength: function (max) {
    this.each(function () {
      var type = this.tagName.toLowerCase();
      var inputType = this.type ? this.type.toLowerCase() : null;
      if (type === 'input' && (inputType === 'text' || inputType === 'email' || inputType === 'password')) {
        // Apply the standard maxLength
        this.maxLength = max;
      } else if (type === 'textarea') {
        this.onkeypress = function (e) {
          var ob = e || event;
          var keyCode = ob.keyCode;
          var hasSelection = document.selection ? document.selection.createRange().text.length > 0 : this.selectionStart !== this.selectionEnd;
          return !(this.value.length >= max && (keyCode > 50 || keyCode === 32 || keyCode === 0 || keyCode === 13) && !ob.ctrlKey && !ob.altKey && !hasSelection);
        };
        this.onkeyup = function () {
          if (this.value.length > max) {
            this.value = this.value.substring(0, max);
          }
        };
      }
    });
  }
});


function initializeMigrationPage() {
  var metric = getShortcutOptions();
  var val = metric.toLowerCase() === 'true' ? true : false;
  $('#shortcut-option').prop('checked', val);
  $('#migrate-btn-text').textCopyToTitle();
}

function showMigrateCheckbox() {
  $('.page-migrate .p-checkbox').show();
}

function settingWelcomeToolbar() {
  setWelcomeToolbarOptions($('#welcome-toolbar-option').is(':checked'));
}

function settingWelcomeWarranty() {
  setWelcomeWarrantyOptions($('#welcome-warranty-option').is(':checked'));
}

function settingToolbar() {
  setToolbarOptions($('#toolbar-option').is(':checked'));
}

function settingWarranty() {
  setWarrantyOptions($('#warranty-option').is(':checked'));
}

function settingShortcut() {
  setShortcutOptions($('#shortcut-option').is(':checked'));
}

function b64EncodeUnicode(str) {
  // first we use encodeURIComponent to get percent-encoded UTF-8,
  // then we convert the percent encodings into raw bytes which
  // can be fed into btoa.
  return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,
    function toSolidBytes(match, p1) {
      return String.fromCharCode('0x' + p1);
    }));
}

function initializeDropbox() {
  dropboxClickBind();
  validateSignUp();
  validateSignIn();
  dToken = 'Basic ' + b64EncodeUnicode(getControlKey());
  $('#su-email, #su-password, #confirm-pwd, #first-name, #last-name, #si-email, #si-password').inputMaxLength(254);
  var dropbox = getDropboxOptions();
  var val = dropbox.toLowerCase() === 'true' ? true : false;
  $('#sign-in-checkbox').prop('checked', val);
  $('#sign-up-checkbox').prop('checked', val);
  dropboxCheckBoxShowButton();
}

function dropboxClickBind() {
  $('body').on('keypress click', '.btn-sign-up', showSignUp);
  $('body').on('keypress click', '.btn-sign-in', showSignIn);
  $('body').on('click', '.sign-up-agree, .sign-in-agree', dropboxCheckBoxShowButton);

  $('body').on('keypress click', '.forgot-pw', function (e) {
    if (e.type === 'keypress') {
      if (e.which !== 13) return false;
    }

    openHtmlWithDefaultBrowser('https://www.dropbox.com/forgot');
    return false;
  });

  $('body').on('keypress click', '.lenovo-offers-terms', function (e) {
    if (e.type === 'keypress') {
      if (e.which !== 13) return false;
    }

    openHtmlWithDefaultBrowser('https://assets.dropbox.com/documents/en-us/legal/dropbox-lenovo-offer-supplemental-terms-conditions.pdf');
    return false;
  });

  $('body').on('keypress click', '.dropbox-terms', function (e) {
    if (e.type === 'keypress') {
      if (e.which !== 13) return false;
    }

    openHtmlWithDefaultBrowser('https://www.dropbox.com/terms');
    return false;
  });

  $('body').on('keypress click', '.view-offer-details', function (e) {
    if (e.type === 'keypress') {
      if (e.which !== 13) return false;
    }

    openHtmlWithDefaultBrowser('https://www.dropbox.com/help/space/lenovo-offer');
    return false;
  });
}

function dropboxCheckBoxShowButton() {
  if ($(".sign-up-agree[type='checkbox']").prop('checked')) {
    $('.btn-sign-up-down').removeClass('disable').removeAttr('disabled');
  } else {
    $('.btn-sign-up-down').addClass('disable').attr('disabled', 'disabled');
  }
  if ($(".sign-in-agree[type='checkbox']").prop('checked')) {
    $('.btn-sign-in-down').removeClass('disable').removeAttr('disabled');
  } else {
    $('.btn-sign-in-down').addClass('disable').attr('disabled', 'disabled');
  }
}

// This is version compare function which takes version numbers of any length and any number size per segment.
// Return values:
// - negative number if v1 < v2
// - positive number if v1 > v2
// - zero if v1 = v2
function compareVersion(v1, v2) {
  const regExStrip0 = '/(\.0+)+$/';
  const segmentsA = v1.replace(regExStrip0, '').split('.');
  const segmentsB = v2.replace(regExStrip0, '').split('.');
  const min = Math.min(segmentsA.length, segmentsB.length);
  for (let i = 0; i < min; i++) {
    const diff = parseInt(segmentsA[i], 10) - parseInt(segmentsB[i], 10);
    if (diff) {
      return diff;
    }
  }
  return segmentsA.length - segmentsB.length;
}

function isVantage2x() {
  if (compareVersion(companionVersion, '4.99.99.99') < 0 ||
    (compareVersion(companionVersion, '20.99.99.99') < 0 && compareVersion(companionVersion, '20.00.00.00') > 0)) {
    return true;
  } else {
    return false;
  }
}

// Use companionVersion to distinguish Vantage 2.x and 3.x, and then open according target page.
function initializeAllDonePage() {
  $('[data-allDone-tangram]').hide();

  $('body').on('keypress click', '#launch-vantage', function (e) {
    if (e.type === 'keypress') {
      if (e.which !== 13) return false;
    }

    openUWP('lenovo-companion:');
    return false;
  });

  $('body').on('keypress click', '#launch-software', function (e) {
    if (e.type === 'keypress') {
      if (e.which !== 13) return false;
    }

    openUWP('lenovo-companion:PARAM?featureId=F45A1A5C-44EB-42C3-B361-025ED702DD7C');
    return false;
  });

  $('body').on('keypress click', '#launch-security-advisor', function (e) {
    if (e.type === 'keypress') {
      if (e.which !== 13) return false;
    }

    if (isVantage2x()) {
      openUWP('lenovo-companion:PARAM?featureId=883B56C4-1348-4478-AB2E-A0909DD121C8&layout=frame&url=https://cms.csw.lenovo.com/en/Tips-and-Tricks/Lenovo-Security-Advisor-101');
    } else {
      openUWP('lenovo-vantage3:security');
    }
    return false;
  });

  $('body').on('keypress click', '#launch-hardware-settings', function (e) {
    if (e.type === 'keypress') {
      if (e.which !== 13) return false;
    }

    if (isVantage2x()) {
      openUWP('lenovo-companion:PARAM?featureId=66F78DA8-2C3F-4651-B958-BA5457F38745');
    } else {
      openUWP('lenovo-vantage3:device-settings');
    }
   return false;
  });

  $('body').on('keypress click', '#launch-discover-more', function (e) {
    if (e.type === 'keypress') {
      if (e.which !== 13) return false;
    }

    if (isVantage2x()) {
      openUWP('lenovo-companion:PARAM?featureId=883B56C4-1348-4478-AB2E-A0909DD121C8&layout=frame&url=https://cms.csw.lenovo.com/en/Tips-and-Tricks/4-Ways-to-Rely-on-Vantage');
    } else {
      openUWP('lenovo-vantage3:dashboard');
    }
    return false;
  });
}

function clearSecretValue() {
  // clear some value
  if (dropboxDefaultEmail === 'none') {
    $('#su-email').val('');
  } else {
    $('#su-email').val(dropboxDefaultEmail);
  }
  $('#si-password').val('');
  $('#su-password').val('');
  $('#confirm-pwd').val('');
  $('.sign-form input').not('[type=checkbox]').removeClass('error');
  // remove some error
  $('.error-1, .error-2').remove();
}

// show sign-up-view
function showSignUp(e) {
  if (e.type === 'keypress') {
    if (e.which !== 13) return false;
  }

  clearSecretValue();
  $('.sign-view').hide();
  $('.sign-up-view').show();
  dropboxCheckBoxShowButton();
  sendDropBoxPageViewEvent();
  return false;
}

// show sign-in-view
function showSignIn(e) {
  if (e.type === 'keypress') {
    if (e.which !== 13) return false;
  }

  clearSecretValue();
  $('.sign-view').hide();
  $('.sign-in-view').show();
  dropboxCheckBoxShowButton();
  sendDropBoxPageViewEvent();
  return false;
}

// if input focus, hide error
function inputFocus() {
  $(this).removeClass('error');
}

$.validator.addMethod('emailDomain', function (value, element) {
  if (value) {
    var emailSplite = value.split('@');
    if (emailSplite.length === 2 ) {
      if (emailSplite[1].indexOf('.') >= 0) {
        return true;
      }
    }
    return false;
  }
  return null;
}, 'The domain portion of the email address is invalid.');

// sign up
function validateSignUp() {
  var validator = $('#sign-up-form').validate({
    errorPlacement: function (error, element) {
      error.addClass('error-1');
      error.appendTo(element.parent());
      element.parent().removeClass('error').addClass('error');
    },
    errorElement: 'p',
    rules: {
      first_name: 'required',
      last_name: 'required',
      email: {
        required: true,
        email: true,
        emailDomain: true
      },
      password: {
        required: true,
        minlength: 6
      },
      confirm_pwd: {
        required: true,
        equalTo: '#su-password'
      },
      agree: 'required'
    },
    messages: {
      email: {
        required: rs.dropbox['error-sign-up-email'],
        email: rs.dropbox['error-sign-up-email'],
        emailDomain: rs.dropbox['error-email-domain']
      },
      first_name: {
        required: rs.dropbox['error-sign-up-fname']
      },
      last_name: {
        required: rs.dropbox['error-sign-up-lname']
      },
      password: {
        required: rs.dropbox['error-password-required'],
        minlength: rs.dropbox['error-password-minlength']
      },
      confirm_pwd: {
        required: rs.dropbox['error-confirm-password-required'],
        equalTo: rs.dropbox['error-confirm-password-equalTo']
      },
      agree: {
        required: rs.dropbox['error-agree']
      }
    },

    submitHandler: function submitSignUp() {
      var dropboxLanguage = navigator.language || navigator.userLanguage;
      createAccount(dToken, dropboxLanguage);
      loadingSkipToggle();
    }
  });

  return validator;
}

// sign in
function validateSignIn() {
  var validator = $('#sign-in-form').validate({
    errorPlacement: function (error, element) {
      error.addClass('error-2');
      error.appendTo(element.parent());
    },
    errorElement: 'p',
    rules: {
      si_email: {
        required: true,
        email: true,
        emailDomain: true
      },
      si_password: {
        required: true,
        minlength: 6
      },
      agree: 'required'
    },
    messages: {
      si_email: {
        required: rs.dropbox['error-sign-in-email'],
        email: rs.dropbox['error-sign-in-email'],
        emailDomain: rs.dropbox['error-email-domain']
      },
      si_password: {
        required: rs.dropbox['error-password-required'],
        minlength: rs.dropbox['error-password-minlength']
      },
      agree: {
        required: rs.dropbox['error-agree']
      }
    },
    submitHandler: function submitSignIn() {
      var dropboxLanguage = navigator.language || navigator.userLanguage;
      login(dToken, dropboxLanguage);
      loadingSkipToggle();
    }
  });

  return validator;
}

// Get Dropbox Authorization
function getAuthorization() {
  if (window.webViewResolver) {
    const dropboxAgent = window.webViewResolver.resolve('DropboxWebAgent');
    return dropboxAgent.getAuthorization();
  }
  return null;
}

// Get Dropbox Account URL
function getCreateAccountUrl() {
  // if (window.webViewResolver) {
  //   const dropboxAgent = window.webViewResolver.resolve('DropboxWebAgent')
  //   return dropboxAgent.callGetCreateAccountUrl()
  // }
  return 'https://api.dropboxapi.com/2/account/create_account';
}

// Get Dropbox login URL
function getLoginUrl() {
  // if (window.webViewResolver) {
  //   const dropboxAgent = window.webViewResolver.resolve('DropboxWebAgent')
  //   var result = dropboxAgent.callGetLoginUrl()
  //   return result
  // }
  // for test
  return 'https://api.dropboxapi.com/2/account/login_with_password';
}

/**
 *
 *
 * @param {*} token token
 * @param {*} lan language
 */
function createAccount(token, lan) {
  var sendData = {
    'email': $('#su-email').val(),
    'password': $('#su-password').val(),
    'first_name': $('#first-name').val(),
    'last_name': $('#last-name').val()
  };
  var caUrl = getCreateAccountUrl();
  $.ajax({
    url: caUrl,
    type: 'POST',
    timeout: 1000 * 20,
    data: JSON.stringify(sendData),
    headers: {
      'Dropbox-API-User-Locale': lan,
      'Content-Type': 'application/json; charset=utf-8',
      'Authorization': token
    },
    success: function (res) {
      // alert(res.oauth2_access_token);
      downloadAndInstallDropbox(res.oauth2_access_token);
    },
    error: function (xhr, status) {
      loadingSkipToggle();
      if (status === 'timeout') {
        xhr.abort();
        logEvent({
          metricsType: 'LogError',
          metricsName: rs.msg['dropbox-unreachable'],
          metricsValue: MetricsErrorCode.DropboxUnreachable
        });
        showGeneralError(rs.msg['dropbox-unreachable']);
      } else if (status === 'error') {
        if (xhr.responseJSON) {
          if (xhr.responseJSON.user_message) {
            showGeneralError(xhr.responseJSON.user_message.text);
          } else if (xhr.responseJSON.error_summary) {
            showGeneralError(xhr.statusText);
          }
        } else if (xhr.statusText) {
          showGeneralError(xhr.statusText);
        }
      } else {
        logEvent({
          metricsType: 'LogError',
          metricsName: rs.msg['dropbox-signup-unknow-error'],
          metricsValue: MetricsErrorCode.DropboxSignupUnknownError
        });
        showGeneralError(rs.msg['dropbox-signup-unknow-error']);
      }
    }
  });

  sendData = null;
}

/**
 * Login Dropbox and download
 * @param {String} token getAuthorization
 * @param {String} lan language
 */
function login(token, lan) {
  var sendData = {
    'email': $('#si-email').val(),
    'password': $('#si-password').val()
  };
  var loginUrl = getLoginUrl();
  $.ajax({
    url: loginUrl,
    type: 'POST',
    timeout: 1000 * 20,
    data: JSON.stringify(sendData),
    headers: {
      'Dropbox-API-User-Locale': lan,
      'Content-Type': 'application/json; charset=utf-8',
      'Authorization': token
    },
    success: function (res) {
      // console.log(res);
      // alert(res.oauth2_access_token);
      downloadAndInstallDropbox(res.oauth2_access_token);
    },
    error: function (xhr, status) {
      loadingSkipToggle();
      if (status === 'timeout') {
        xhr.abort();
        showGeneralError(rs.msg['dropbox-unreachable']);
      } else if (status === 'error') {
        if (xhr.responseJSON) {
          if (xhr.responseJSON.user_message) {
            showGeneralError(xhr.responseJSON.user_message.text);
          } else if (xhr.responseJSON.error_summary) {
            showGeneralError(xhr.statusText);
          }
        } else if (xhr.statusText) {
          showGeneralError(xhr.statusText);
        }
      } else {
        logEvent({
          metricsType: 'LogError',
          metricsName: rs.msg['dropbox-signin-unknow-error'],
          metricsValue: MetricsErrorCode.DropboxSigninUnknownError
        });
        showGeneralError(rs.msg['dropbox-signin-unknow-error']);
      }
    }
  });

  sendData = null;
}
function downloadAndInstallDropbox(val) {
  downloadAndInstall(dropboxPageName, dropboxGuid, val, 'downloadDropboxCallback');
  loadingSkipToggle();
  clearSecretValue();
  goNext(dropboxPageName);
}
function downloadDropboxCallback(param) {
  // do nothing
}
function loadingSkipToggle() {
  if ($('.btn-sign-skip').css('display') === 'block') {
    $('.dropbox-loading').show();
    $('.dropbox-mask').show();
    setTabIndex(TabIndexDisabled);
    $('.btn-sign-skip').hide();
  } else {
    $('.dropbox-loading').hide();
    $('.dropbox-mask').hide();
    setTabIndex(TabIndexEnabled);
    $('.btn-sign-skip').show();
  }
}

/** ****************** Apps for you start********************/
function initializeAppsForYou() {
  appsCheckBoxShowButton();
  $('body').on('click', '.apps-container .input_check', appsCheckBoxShowButton);
  $('[data-toggle="tooltip"]').attr('title', function () {
    return tooltipTitle($(this));
  });
  $('[data-toggle="tooltip"]').tooltip({
    html: true,
    trigger: 'hover',
    placement: 'auto left'
  });
  // $('body').on('focus', '.apps-container .input_check', function() {
  //   $(this).parent().parent().find('.apps-tip').tooltip('show');
  // });
  // $('body').on('blur', '.apps-container .input_check', function() {
  //   $(this).parent().parent().find('.apps-tip').tooltip('hide');
  // });
}
function tooltipTitle(e) {
  var tipTitle = e.find('.apps-text').text();
  var tipDesc = e.find('.tooltips-text').text();
  var tipHtml = '<p class=\'app-name mb-1\'>' + tipTitle + '</p>' +
                '<p class=\'app-description mb-0\'>' + tipDesc + '</p>';
  return tipHtml;
}

function appsCheckBoxShowButton() {
  var oAppContainer = $('.apps-container');
  var oCheckboxs = oAppContainer.find('input:checkbox');
  var notChecked = oCheckboxs.not('input:checked');
  if (notChecked.length === oCheckboxs.length) {
    $('#confirm-and-download').addClass('disable').attr('disabled', 'disabled');
  } else {
    $('#confirm-and-download').removeClass('disable').removeAttr('disabled');
  }
}

function deleteLastCharacter(str) {
  return str.substr(0, str.length - 1);
}

function downloadAndInstallConfirmApps() {
  var webLinkList = '';
  var executeFileList = '';
  var oAppContainer = $('.apps-container');
  var oCheckboxs = oAppContainer.find('input:checkbox');
  var checkedItems = oCheckboxs.filter('input:checked');

  $.each(checkedItems, function (index) {
    if (appList[this.id].type === WebLinkType) {
      webLinkList += appList[this.id].guid + ';';
    }

    if (appList[this.id].type === ExecuteFileType) {
      executeFileList += appList[this.id].guid + ';';
    }
  });

  webLinkList = deleteLastCharacter(webLinkList);
  executeFileList = deleteLastCharacter(executeFileList);

  if (webLinkList !== '') createWebLink(webLinkList);
  if (executeFileList !== '') downloadAndInstall(appsforyouPageName, executeFileList);
}

/** ************* Apps for you end **************** */

function initializeCloseAppPage() {
  $('#close-got-it').on('click', function () {
    closeFreApp();
    return false;
  });

  $('#close-cancel').on('click', function () {
    $('#' + pageInfo.currentPageName).css('visibility', 'visible');
    showPageScrollBar('#' + pageInfo.currentPageName);
    $('#closeApp').css('visibility', 'hidden');
    hidePageScrollBar('#closeApp');
    return false;
    });

    $('#close-remove-this').on('click', function () {
        uninstallApp();
        return false;
    });
}

function initializeDialog() {
  oInternetDiv = $('#dialog-panel-internet');
  oErrorDiv = $('#dialog-panel-error');
  oAppsDiv = $('#dialog-panel-apps');
  setContainerSize();
  setDrag();
}

function showDialog() {
  $('.common-dialog').show();
}

function hideDialog() {
  if (isPopupShow()) return;
  $('.common-dialog').hide();
}

function getViewSize() {
  return {
    'w': $('body').width(),
    'h': $('body').height()
    // 'w': window.innerWidth || $(document).width(),
    // 'h': window.innerHeight || $(document).height()
  };
}

function setContainerSize() {
  var size = getViewSize();

  var offsetInternetL = (size.w - oInternetDiv.outerWidth()) / 2;
  var offsetInternetT = (size.h - oInternetDiv.outerHeight()) / 2;
  oInternetDiv.css({
    'left': offsetInternetL,
    'top': offsetInternetT
  });
  var offsetErrorL = (size.w - oErrorDiv.outerWidth()) / 2;
  var offsetErrorT = (size.h - oErrorDiv.outerHeight()) / 2;
  oErrorDiv.css({
    'left': offsetErrorL,
    'top': offsetErrorT
  });
  var offsetAppsL = (size.w - oAppsDiv.outerWidth()) / 2;
  var offsetAppsT = (size.h - oAppsDiv.outerHeight()) / 2;
  oAppsDiv.css({
    'left': offsetAppsL,
    'top': offsetAppsT
  });
}

function tryAgain(e) {
  if (getNetworkState()) {
    hidePopup(e);

    if (!initializeFinished) {
      runApp();
    }
  }
}

// setContainerSize();
// window.onresize = setContainerSize;

/**
 * Show dialog
 * @param {String} errortext error text
 * @param {String} errorType error type
 * @param {Object} callback function
 */
function showPopup(errortext, errorType, callback) {
  $('.common-dialog').show();
  $('.dialog-title').text(appName);
  setTabIndex(TabIndexDisabled);
  if (errorType === noInternetError) {
    logEvent({
      metricsType: 'LogError',
      metricsName: rs.msg['not-found'],
      metricsValue: MetricsErrorCode.InternetNotFound
    });
    $('#dialog-panel-internet').show();
    $('#internet-tryagain-btn').off('click').on('click', tryAgain);
    $('#dialog-close-internet').off('keypress click').on('keypress click', closeFreApp);
  } else if (errorType === generalError) {
    $('#dialog-panel-error').show();
    $('.dialog-content-error').find('.failed-text').text(errortext);
    if (typeof (callback) !== 'undefined') {
      $('#dialog-close-general, #general-gotit-btn').off('keypress click').on('keypress click', callback);
    } else {
      $('#dialog-close-general, #general-gotit-btn').off('keypress click').on('keypress click', hidePopup);
    }
  } else if (errorType === downloadDialog) {
    $('#dialog-panel-apps').show();
    $('#dialog-apps-cancel, #dialog-close-apps').off('keypress click').on('keypress click', function (e) {
      logEventForItemClick($(this));
      hidePopup(e);
    });
    $('#dialog-apps-ok').off('click').on('click', function (e) {
      logEventForItemClick($(this));
      hidePopup(e);
      sendMetricOfConfirmApps();
      downloadAndInstallConfirmApps();
      goNext(appsforyouPageName);
      return false;
    });
  }
}

var TabIndexEnabled = 0;
var TabIndexDisabled = 1;
var currentTabState = TabIndexEnabled;

function setTabIndex(tabState) {
  if (currentTabState === tabState) return;

  currentTabState = tabState;

  if (pageInfo.currentPageName === '') return;

  var thisPage = '#' + pageInfo.currentPageName;
  $(thisPage).find('[tabIndex]').each(function () {
    $(this).attr('tabIndex', -parseFloat($(this).attr('tabIndex')));
  });
}

function sendMetricOfMetricCheckbox() {
  var value = $('#metric').is(':checked') === true ? 'on' : 'off';
  logEvent({
    metricsType: 'ItemClick',
    metricsName: 'Features.WelcomePage.UsageStatisticsToggleButton',
    metricsParent: 'Features.WelcomePage',
    metricsValue: value
  });
}

function sendMetricOfToolbarCheckbox() {
  var value = $('#welcome-toolbar-option').is(':checked') === true ? 'on' : 'off';
  logEvent({
    metricsType: 'ItemClick',
    metricsName: 'Features.WelcomePage.AddToolbarToggleButton',
    metricsParent: 'Features.WelcomePage',
    metricsValue: value
  });
}

function sendMetricOfWarrantyCheckbox() {
  var value = $('#welcome-warranty-option').is(':checked') === true ? 'on' : 'off';
  logEvent({
    metricsType: 'ItemClick',
    metricsName: 'Features.WelcomePage.WarrantyToggleButton',
    metricsParent: 'Features.WelcomePage',
    metricsValue: value
  });
}


function sendMetricOfConfirmApps() {
  var confirmAppList = '';
  var oAppContainer = $('.apps-container');
  var oCheckboxs = oAppContainer.find('input:checkbox');
  var checkedItems = oCheckboxs.filter('input:checked');

  $.each(checkedItems, function (index) {
    confirmAppList += appList[this.id].name + ','
  });

  confirmAppList = deleteLastCharacter(confirmAppList);

  if (confirmAppList !== '') {
    logEvent({
      metricsType: 'ItemClick',
      metricsName: 'Features.AppsForYou.ConfirmDialog.ConfirmButton',
      metricsParent: 'Features.AppsForYou',
      metricsValue: confirmAppList
    });
  }
}

function initlalizeClickBind() {
  $('#premium-care-back-btn, #migrate-back-btn, #apps-for-you-back-btn, #vantage-back-btn, #lid-back-btn, #alldone-back-btn').on('click', function (e) {
    var eventTriggeredPage = '';
    switch (e.target.id) {
    case 'premium-care-back-btn':
      eventTriggeredPage = premiumCarePageName;
      break;
    case 'migrate-back-btn':
      eventTriggeredPage = migratePageName;
      break;
    case 'apps-for-you-back-btn':
      eventTriggeredPage = appsforyouPageName;
      break;
    case 'vantage-back-btn':
      eventTriggeredPage = vantagePageName;
      break;
    case 'lid-back-btn':
      eventTriggeredPage = lenovoidPageName;
      break;
    case 'alldone-back-btn':
      eventTriggeredPage = alldonePageName;
      break;
    default:break;
    }
    goBack(eventTriggeredPage);
    return false;
  });

  $('#premium-care-next-btn, #migrate-next-btn, #apps-for-you-skip-btn, #lid-skip-btn').on('click', function (e) {
    var eventTriggeredPage = '';
    switch (e.target.id) {
    case 'premium-care-next-btn':
      eventTriggeredPage = premiumCarePageName;
      break;
    case 'migrate-next-btn':
      eventTriggeredPage = migratePageName;
      break;
    case 'apps-for-you-skip-btn':
      eventTriggeredPage = appsforyouPageName;
      break;
    case 'lid-skip-btn':
      eventTriggeredPage = lenovoidPageName;
      break;
    default:break;
    }
    goNext(eventTriggeredPage);
    return false;
  });
  
  $('#migrate-download').on('click', function () {
    settingShortcut();
    downloadAndInstallMigration();
    return false;
  });

  $('#confirm-and-download').on('click', function () {
    showDownloadApps();
    return false;
  });

  $('#dropbox-back-btn').on('click', function () {
    clearSecretValue();
    goBack(dropboxPageName);
    return false;
  });

  $('#dropbox-signup-next-btn, #dropbox-signin-next-btn').on('click', function () {
    clearSecretValue();
    goNext(dropboxPageName);
    return false;
  });

  $('#welcome-next-btn').on('click', function () {
    sendMetricOfMetricCheckbox();
    sendMetricOfToolbarCheckbox();
    sendMetricOfWarrantyCheckbox();
    settingWelcomeToolbar();
    settingWelcomeWarranty();
    goNext(welcomePageName);
    return false;
  });

  $('#metric').on('click', function () {
    settingMetrics();
  });

  $('#vantage-next-btn').on('click', function () {
    settingToolbar();
    settingWarranty();
    goNext(vantagePageName);
    return false;
  });

  $('#lid-next-btn').on('click', function () {
    loginLenovoID();
    return false;
  });

  $('#privacy-policy-btn').on('click', function () {
    openHtmlWithDefaultBrowser('https://www.lenovo.com/us/en/privacy/');
    return false;
  });
}

function initializePages() {
  initializeMigrationPage();
  initializeAppsForYou();
  initializeDropbox();
  initializeWelcomePage();
  initializePremiumCarePage();
  initializeVantagePage();
  initializeAllDonePage();
  initializeCloseAppPage();
  initlalizeClickBind();
}

function isPopupShow(type) {
  var ret = false;

  if (typeof (type) === 'undefined') return $('#dialog-panel-internet').is(':visible') || $('#dialog-panel-error').is(':visible') || $('#dialog-panel-apps').is(':visible');

  switch (type) {
  case noInternetError:
    ret = $('#dialog-panel-internet').is(':visible'); break;
  case generalError:
    ret = $('#dialog-panel-error').is(':visible'); break;
  case downloadDialog:
    ret = $('#dialog-panel-apps').is(':visible'); break;
  default:break;
  }

  return ret;
}

function showNoInternetError() {
  if (isPopupShow(noInternetError)) return;
  hideOtherDialog();
  showPopup('', noInternetError);
}

function hideOtherDialog() {
  $('#dialog-panel-apps').hide();
  $('#dialog-panel-error').hide();
}

function showGeneralError(text, callback) {
  if (isPopupShow(noInternetError)) return;
  if (isPopupShow(generalError)) return;
  hideOtherDialog();
  showPopup(text, generalError, callback);
}

function showDownloadApps() {
  if (isPopupShow()) return;
  showPopup('', downloadDialog);
}

function hidePopup(e) {
  var target = $('#' + e.target.id);
  target.parents('.dialog-panel').hide();
  setTabIndex(TabIndexEnabled);
  if ($('#dialog-panel-internet').css('display') === 'none' &&
      $('#dialog-panel-error').css('display') === 'none' &&
      $('#dialog-panel-apps').css('display') === 'none') {
    $('.common-dialog').hide();
  }

  return false;
}

/** ***************** drag *********************/
function setDrag() {
  oInternetDiv.on('mousedown', dragDialog);
  oErrorDiv.on('mousedown', dragDialog);
  oAppsDiv.on('mousedown', dragDialog);
  function dragDialog(mousedownEnent) {
    var oDiv = $(this);
    var mousedown = mousedownEnent || window.event;
    var reX = mousedown.clientX - oDiv.offset().left;
    var reY = mousedown.clientY - oDiv.offset().top;
    var MX = $('body').width() - oDiv.outerWidth();
    var MY = $('body').height() - oDiv.outerHeight();

    $(document).on('mousemove', function (mousemoveEvent) {
      var mousemove = mousemoveEvent || window.event;
      var X = mousemove.clientX - reX;
      var Y = mousemove.clientY - reY;
      if (X < 0) {
        X = 0;
      } else if (X > MX) {
        X = MX;
      }
      if (Y < 0) {
        Y = 0;
      } else if (Y > MY) {
        Y = MY;
      }
      oDiv.css({'top': Y + 'px', 'left': X + 'px'});
    });
    $(document).on('mouseup', function () {
      $(document).off('mousemove');
    });
  }
}
/** ***************** dialog end *********************/
$(document).keydown(function (event) {
  if (event.ctrlKey === true && (event.which === 61 || event.which === 107 || event.which === 173 || event.which === 109  || event.which === 187  || event.which === 189  ) ) {
    event.preventDefault();
  }
  // 107 Num Key  +
  // 109 Num Key  -
  // 173 Min Key  hyphen/underscor Hey
  // 61 Plus key  +/= key
});

$(window).bind('mousewheel DOMMouseScroll', function (event) {
  if (event.ctrlKey === true) {
    event.preventDefault();
  }
});

/** ********** loading start ************/
function showOpeningAnimation() {
  $('.opening-animation').show();
}
function hideOpeningAnimation() {
  $('.opening-animation').hide();
}
/** ********** loading end ************/

function setMiniTimeStartupAnimation() {
  setTimeout(function miniAnimation() {
    miniAnimationTimePassed = true;

    if (initializeAllDone()) {
      showInitiaPage();
      hideOpeningAnimation();
    }
  }, miniAnimationSeconds * 1000);
}

function handleInitializeTimeout() {
  setTimeout(function timeout() {
    if (initializeAllDone()) return;
    hideOpeningAnimation();
    showGeneralError(rs.msg['sso-common-info'], closeFreApp);
  }, initializeTimeoutSeconds * 1000);
}

function prerequisiteCheck() {
  if (!isLenovoDevice()) {
    logEvent({
      metricsType: 'LogError',
      metricsName: rs.msg['only-run-lenovo-device'],
      metricsValue: MetricsErrorCode.OnlyRunLenovoDevice
    });
    showGeneralError(rs.msg['only-run-lenovo-device'], closeFreApp);
    return false;
  }

  if (!isNetworkConnected()) {
    showNoInternetError();
    return false;
  }
  return true;
}

var initializeFinished = false;

function setupAPPList() {
    var appContainer = $('.apps-container');
    var template = $('#app-item-template').html();
    
    var appArray = $.map(appList, function(item, index) {
      item.id = index;
      return item;
    });
    
    appArray.sort(function (a1, a2) {
        return a1.tabIndex - a2.tabIndex;
    });
    
    $.each(appArray, function (idx, item) {
      var element = template;
      element = element.replace(/\$\{tag\}/g, item.tag);
      element = element.replace(/\$\{tabIndex\}/g, item.tabIndex);
      element = element.replace(/\$\{metrics\}/g, item.metrics);
      element = element.replace(/\$\{id\}/g, item.id);
      element = element.replace(/\$\{name\}/g, item.name);
      element = element.replace(/\$\{tip\}/g, item.defaultTip === null ? '' : item.defaultTip);
      appContainer.append(element);
    });
}

function runApp() {
  handleInitializeTimeout();
  showOpeningAnimation();
  setMiniTimeStartupAnimation();
  initializePages();
  getSubscriptionXML('getXML');
  getLIDStatus();
  getSoftwareEntitledState('SoftwareEntitled');
  companionVersion = getCompanionVersion();
  initializeFinished = true;
}

$().ready(function () {
  setupAPPList();
  rs = loadStrings();
  initializeDialog();
  registerMetricEvents();

  if (prerequisiteCheck()) {
    runApp();
  }
});
