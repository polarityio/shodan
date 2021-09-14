polarity.export = PolarityComponent.extend({
  data: Ember.computed.alias('block.data'),
  details: Ember.computed.alias('block.data.details'),
  timezone: Ember.computed("Intl", function () {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  }),
  showDetails: false,
  entity: Ember.computed.alias('block.entity'),
  message: '',
  errorMessage: null,
  isRunning: false,
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
    }
  }
});
