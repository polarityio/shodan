polarity.export = PolarityComponent.extend({
    details: Ember.computed.alias('block.data.details'),
    showDetails: false,
    actions: {
        toggleDetails: function(){
            this.toggleProperty('showDetails');
        }
    }
});
