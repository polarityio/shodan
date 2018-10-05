'use strict';

polarity.export = PolarityComponent.extend({
    details: Ember.computed.alias('block.data.details'),
    summaryTags: Ember.computed('details.tags', function(){
        let summaryTags = [];

        if(this.get('details.city')){
            summaryTags.push(this.get('details.city'));
        }

        if(this.get('details.isp')){
            summaryTags.push(this.get('details.isp'));
        }

        if(this.get('details.country_name')){
            summaryTags.push(this.get('details.country_name'));
        }

        if(this.get('details.org')){
            summaryTags.push(this.get('details.org'));
        }

        let tags = this.get('details.tags');
        if(Array.isArray(tags)){
            summaryTags = summaryTags.concat(tags);
        }

        if(summaryTags.length === 0){
            summaryTags.push('No Tags');
        }
        return summaryTags;
    })
});

