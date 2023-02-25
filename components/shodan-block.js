polarity.export = PolarityComponent.extend({
  data: Ember.computed.alias('block.data'),
  details: Ember.computed.alias('block.data.details'),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  showCopyMessage: false,
  uniqueIdPrefix: '',
  entity: Ember.computed.alias('block.entity'),
  message: '',
  errorMessage: null,
  isRunning: false,
  init() {
    let array = new Uint32Array(5);
    this.set('uniqueIdPrefix', window.crypto.getRandomValues(array).join(''));
    if (!this.get('block._state')) {
      this.set('block._state', {});
      this.set('block._state.showDetails', false);
    }

    this._super(...arguments);
  },
  actions: {
    toggleDetails: function () {
      this.toggleProperty('block._state.showDetails');
    },
    tryAgain: function () {
      const outerThis = this;

      this.set('message', '');
      this.set('errorMessage', '');
      this.set('isRunning', true);

      this.sendIntegrationMessage({ data: { entity: this.entity } })
        .then((data) => {
          outerThis.set('message', 'Success!');
          outerThis.set('block.data.summary', data.summary);
          outerThis.set('details', data.details);
        })
        .catch((err) => {
          outerThis.set(
            'errorMessage',
            `Failed on Retry: ${err.message || err.title || err.description || 'Unknown Reason'}`
          );
        })
        .finally(() => {
          this.set('isRunning', false);
          outerThis.get('block').notifyPropertyChange('data');
        });
    },
    copyData: function () {
      const savedDetails = this.get('block._state.showDetails');
      this.set('block._state.showDetails', true);

      Ember.run.scheduleOnce(
        'afterRender',
        this,
        this.copyElementToClipboard,
        `shodan-container-${this.get('uniqueIdPrefix')}`
      );

      Ember.run.scheduleOnce('destroy', this, this.restoreCopyState, savedDetails);
    }
  },
  copyElementToClipboard(element) {
    window.getSelection().removeAllRanges();
    let range = document.createRange();

    range.selectNode(typeof element === 'string' ? document.getElementById(element) : element);
    window.getSelection().addRange(range);
    document.execCommand('copy');
    window.getSelection().removeAllRanges();
  },
  restoreCopyState(savedDetails) {
    this.set('showCopyMessage', true);
    this.set('block._state.showDetails', savedDetails);

    setTimeout(() => {
      if (!this.isDestroyed) {
        this.set('showCopyMessage', false);
      }
    }, 2000);
  }
});
