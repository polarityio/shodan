'use strict';

polarity.export = PolarityComponent.extend({
  details: Ember.computed.alias('block.data.details'),
  entity: Ember.computed.alias('block.entity'),
  actions: {
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
