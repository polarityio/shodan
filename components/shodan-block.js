polarity.export = PolarityComponent.extend({
  data: Ember.computed.alias('block.data'),
  details: Ember.computed.alias('block.data.details'),
  timezone: Ember.computed('Intl', function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  showDetails: false,
  showCopyMessage: false,
  uniqueIdPrefix: '',
  entity: Ember.computed.alias('block.entity'),
  message: '',
  errorMessage: null,
  isRunning: false,
  init () {
    let array = new Uint32Array(5);
    this.set('uniqueIdPrefix', window.crypto.getRandomValues(array).join(''));

    this._super(...arguments);
  },
  actions: {
    toggleDetails: function () {
      this.toggleProperty('showDetails');
    },
    tryAgain: function () {
      const outerThis = this;

      this.set('message', '');
      this.set('errorMessage', '');
      this.set('isRunning', true);

      this.sendIntegrationMessage({ data: { entity: this.entity } })
        .then((newDetails) => {
          outerThis.set('message', 'Success!');
          outerThis.set('details', newDetails);
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

      console.log(this.get('details'));

      Ember.run.scheduleOnce(
        'afterRender',
        this,
        this.copyElementToClipboard,
        `shodan-container-${this.get('uniqueIdPrefix')}`
      );

      Ember.run.scheduleOnce('destroy', this, this.restoreCopyState, savedDetails);
    }
  },
  copyElementToClipboard (element) {
    window.getSelection().removeAllRanges();
    let range = document.createRange();

    range.selectNode(typeof element === 'string' ? document.getElementById(element) : element);
    window.getSelection().addRange(range);
    document.execCommand('copy');
    window.getSelection().removeAllRanges();
  },
  getElementRance (element) {
    let range = document.createRange();
    range.selectNode(typeof element === 'string' ? document.getElementById(element) : element);
    return range;
  },
  restoreCopyState (savedDetails) {
    this.set('showCopyMessage', true);

    this.set('block._state.showDetails', savedDetails);

    setTimeout(() => {
      if (!this.isDestroyed) {
        this.set('showCopyMessage', false);
      }
    }, 2000);
  }
});
