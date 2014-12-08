// See lms/static/js/RequireJS-namespace-undefine.js
RequireJS.define = define;

define([
    'jquery',
    'sinon',
    'backbone',
    'js/common_helpers/template_helpers',
    'js/search/views/SearchForm',
    'js/search/views/SearchItemView',
    'js/search/views/SearchListView',
    'js/search/models/SearchResult',
    'js/search/collections/SearchCollection',
    'js/search/SearchRouter',
    'js/search/SearchApp'
], function(
    $,
    Sinon,
    Backbone,
    TemplateHelpers,
    SearchForm,
    SearchItemView,
    SearchListView,
    SearchResult,
    SearchCollection,
    SearchRouter,
    SearchApp
) {
    'use strict';

    describe('SearchForm', function () {

        beforeEach(function () {
            loadFixtures('js/fixtures/search_form.html');
            this.form = new SearchForm();
            this.onClear = jasmine.createSpy('onClear');
            this.onSearch = jasmine.createSpy('onSearch');
            this.form.on('clear', this.onClear);
            this.form.on('search', this.onSearch);
        });

        it('prevents default action on submit', function () {
            expect(this.form.submitForm()).toEqual(false);
        });

        it('trims input string', function () {
            var term = '  search string  ';
            $('.search-field').val(term);
            $('form').trigger('submit');
            expect(this.onSearch).toHaveBeenCalledWith($.trim(term));
        });

        it('handles calls to doSearch', function () {
            var term = '  search string  ';
            $('.search-field').val(term);
            this.form.doSearch(term);
            expect(this.onSearch).toHaveBeenCalledWith($.trim(term));
            expect($('.search-field').val()).toEqual(term);
            expect($('.search-field')).toHaveClass('is-active');
            expect($('.search-button')).toBeHidden();
            expect($('.cancel-button')).toBeVisible();
        });

        it('triggers a search event and changes to active state', function () {
            var term = 'search string';
            $('.search-field').val(term);
            $('form').trigger('submit');
            expect(this.onSearch).toHaveBeenCalledWith(term);
            expect($('.search-field')).toHaveClass('is-active');
            expect($('.search-button')).toBeHidden();
            expect($('.cancel-button')).toBeVisible();
        });

        it('clears search when clicking on cancel button', function () {
            $('.search-field').val('search string');
            $('.cancel-button').trigger('click');
            expect($('.search-field')).not.toHaveClass('is-active');
            expect($('.search-button')).toBeVisible();
            expect($('.cancel-button')).toBeHidden();
            expect($('.search-field')).toHaveValue('');
        });

        it('clears search when search box is empty', function() {
            $('.search-field').val('');
            $('form').trigger('submit');
            expect(this.onClear).toHaveBeenCalled();
            expect($('.search-field')).not.toHaveClass('is-active');
            expect($('.cancel-button')).toBeHidden();
            expect($('.search-button')).toBeVisible();
        });

    });


    describe('SearchItemView', function () {

        beforeEach(function () {
            TemplateHelpers.installTemplate('templates/courseware_search/search_item');
            this.model = {
                attributes: {
                    location: ['section', 'subsection', 'unit'],
                    content_type: 'Video',
                    excerpt: 'A short excerpt.',
                    url: 'path/to/content'
                }
            };
            this.item = new SearchItemView({ model: this.model });
        });

        it('has useful html attributes', function () {
            expect(this.item.$el).toHaveAttr('role', 'region');
            expect(this.item.$el).toHaveAttr('aria-label', 'search result');
        });

        it('renders underscore template', function () {
            var href = this.model.attributes.url;
            var breadcrumbs = 'section ▸ subsection ▸ unit';

            this.item.render();
            expect(this.item.$el).toContainText(this.model.attributes.content_type);
            expect(this.item.$el).toContainText(this.model.attributes.excerpt);
            expect(this.item.$el.find('a[href="'+href+'"]')).toHaveAttr('href', href);
            expect(this.item.$el).toContainText(breadcrumbs);
        });

    });


    describe('SearchResult', function () {

        beforeEach(function () {
            this.result = new SearchResult();
        });

        it('has properties', function () {
            expect(this.result.get('location')).toBeDefined();
            expect(this.result.get('content_type')).toBeDefined();
            expect(this.result.get('excerpt')).toBeDefined();
            expect(this.result.get('url')).toBeDefined();
        });

    });


    describe('SearchCollection', function () {

        beforeEach(function () {
            this.server = Sinon.fakeServer.create();
            this.collection = new SearchCollection();

            this.onSearch = jasmine.createSpy('onSearch');
            this.collection.on('search', this.onSearch);

            this.onNext = jasmine.createSpy('onNext');
            this.collection.on('next', this.onNext);

            this.onError = jasmine.createSpy('onError');
            this.collection.on('error', this.onError);
        });

        afterEach(function () {
            this.server.restore();
        });

        it('appends course_id to url', function () {
            var collection = new SearchCollection([], { course_id: 'edx101' });
            expect(collection.url).toEqual('/search/edx101');
        });

        it('sends a request and parses the json result', function () {
            this.collection.performSearch('search string');
            var response = {
                total: 2,
                access_denied_count: 1,
                results: [{
                    data: {
                        location: ['section', 'subsection', 'unit'],
                        url: '/some/url/to/content',
                        content_type: 'text',
                        excerpt: 'this is a short excerpt'
                    }
                }]
            };
            this.server.respondWith('POST', this.collection.url, [200, {}, JSON.stringify(response)]);
            this.server.respond();

            expect(this.onSearch).toHaveBeenCalled();
            expect(this.collection.totalCount).toEqual(1);
            expect(this.collection.accessDeniedCount).toEqual(1);
            expect(this.collection.page).toEqual(0);
            expect(this.collection.first().attributes).toEqual(response.results[0].data);
        });

        it('handles errors', function () {
            this.collection.performSearch('search string');
            this.server.respond();
            expect(this.onSearch).not.toHaveBeenCalled();
            expect(this.onError).toHaveBeenCalled();
        });

        it('loads next page', function () {
            var response = { total: 35, results: [] };
            this.collection.loadNextPage();
            this.server.respond('POST', this.collection.url, [200, {}, JSON.stringify(response)]);
            expect(this.onNext).toHaveBeenCalled();
            expect(this.onError).not.toHaveBeenCalled();
        });

        it('sends correct paging parameters', function () {
            this.collection.performSearch('search string');
            var response = { total: 52, results: [] };
            this.server.respondWith('POST', this.collection.url, [200, {}, JSON.stringify(response)]);
            this.server.respond();
            this.collection.loadNextPage();
            this.server.respond();
            spyOn($, 'ajax');
            this.collection.loadNextPage();
            expect($.ajax.mostRecentCall.args[0].url).toEqual(this.collection.url);
            expect($.ajax.mostRecentCall.args[0].data).toEqual({
                search_string : 'search string',
                page_size : this.collection.pageSize,
                page_index : 2
            });
        });

        it('has next page', function () {
            var response = { total: 35, access_denied_count: 5, results: [] };
            this.collection.performSearch('search string');
            this.server.respond('POST', this.collection.url, [200, {}, JSON.stringify(response)]);
            expect(this.collection.hasNextPage()).toEqual(true);
            this.collection.loadNextPage();
            this.server.respond();
            expect(this.collection.hasNextPage()).toEqual(false);
        });

        it('aborts any previous request', function () {
            var response = { total: 35, results: [] };

            this.collection.performSearch('old search');
            this.collection.performSearch('new search');
            this.server.respond('POST', this.collection.url, [200, {}, JSON.stringify(response)]);
            expect(this.onSearch.calls.length).toEqual(1);

            this.collection.performSearch('old search');
            this.collection.cancelSearch();
            this.server.respond('POST', this.collection.url, [200, {}, JSON.stringify(response)]);
            expect(this.onSearch.calls.length).toEqual(1);

            this.collection.loadNextPage();
            this.collection.loadNextPage();
            this.server.respond('POST', this.collection.url, [200, {}, JSON.stringify(response)]);
            expect(this.onNext.calls.length).toEqual(1);
        });

        describe('reset state', function () {

            beforeEach(function () {
                this.collection.page = 2;
                this.collection.totalCount = 35;
            });

            it('resets state when performing new search', function () {
                this.collection.performSearch('search string');
                expect(this.collection.page).toEqual(0);
                expect(this.collection.totalCount).toEqual(0);
            });

            it('resets state when canceling a search', function () {
                this.collection.cancelSearch();
                expect(this.collection.page).toEqual(0);
                expect(this.collection.totalCount).toEqual(0);
            });

        });

    });


    describe('SearchListView', function () {

        beforeEach(function () {
            setFixtures(
                '<section id="courseware-search-results" data-course-name="Test Course"></section>' +
                '<section id="course-content"></section>');

            TemplateHelpers.installTemplate('templates/courseware_search/search_item');
            TemplateHelpers.installTemplate('templates/courseware_search/search_list');
            TemplateHelpers.installTemplate('templates/courseware_search/search_loading');
            TemplateHelpers.installTemplate('templates/courseware_search/search_error');

            var MockCollection = Backbone.Collection.extend({
                hasNextPage: function (){}
            });
            this.collection = new MockCollection();

            // spy on these methods before they are bound to events
            spyOn(SearchListView.prototype, 'render').andCallThrough();
            spyOn(SearchListView.prototype, 'renderNext').andCallThrough();
            spyOn(SearchListView.prototype, 'showErrorMessage').andCallThrough();

            this.listView = new SearchListView({ collection: this.collection });
        });

        it('shows loading message', function () {
            this.listView.showLoadingMessage();
            expect($('#course-content')).toBeHidden();
            expect(this.listView.$el).toBeVisible();
            expect(this.listView.$el).not.toBeEmpty();
        });

        it('shows error message', function () {
            this.listView.showErrorMessage();
            expect($('#course-content')).toBeHidden();
            expect(this.listView.$el).toBeVisible();
            expect(this.listView.$el).not.toBeEmpty();
        });

        it('returns to content', function () {
            this.listView.clear();
            expect($('#course-content')).toBeVisible();
            expect(this.listView.$el).toBeHidden();
            expect(this.listView.$el).toBeEmpty();
        });

        it('handles events', function () {
            this.collection.trigger('search');
            this.collection.trigger('next');
            this.collection.trigger('error');

            expect(this.listView.render).toHaveBeenCalled();
            expect(this.listView.renderNext).toHaveBeenCalled();
            expect(this.listView.showErrorMessage).toHaveBeenCalled();
        });

        it('renders a message when there are no results', function () {
            this.collection.reset();
            this.listView.render();
            expect(this.listView.$el).toContainText('no results');
            expect(this.listView.$el.find('ol')).not.toExist();
        });

        it('renders search results', function () {
            var searchResults = [{
                location: ['section', 'subsection', 'unit'],
                url: '/some/url/to/content',
                content_type: 'text',
                excerpt: 'this is a short excerpt'
            }];
            this.collection.set(searchResults);
            this.collection.totalCount = 1;

            this.listView.render();
            expect(this.listView.$el.find('ol')[0]).toExist();
            expect(this.listView.$el.find('li')).toHaveLength(1);
            expect(this.listView.$el).toContainText('Test Course');
            expect(this.listView.$el).toContainText('this is a short excerpt');

            this.collection.set(searchResults);
            this.collection.totalCount = 2;
            this.listView.renderNext();
            expect(this.listView.$el.find('.search-count-total').text()).toEqual('2');
            expect(this.listView.$el.find('li')).toHaveLength(2);
        });

        it('shows a link to load more results', function () {
            this.collection.totalCount = 123;
            this.collection.hasNextPage = function () { return true; };
            this.listView.render();
            expect(this.listView.$el.find('a.search-load-next')[0]).toExist();

            this.collection.totalCount = 123;
            this.collection.hasNextPage = function () { return false; };
            this.listView.render();
            expect(this.listView.$el.find('a.search-load-next')[0]).not.toExist();
        });

        it('triggers an event for next page', function () {
            var onNext = jasmine.createSpy('onNext');
            this.listView.on('next', onNext);
            this.collection.totalCount = 123;
            this.collection.hasNextPage = function () { return true; };
            this.listView.render();
            this.listView.$el.find('a.search-load-next').click();
            expect(onNext).toHaveBeenCalled();
        });

        it('shows a spinner when loading more results', function () {
            this.collection.totalCount = 123;
            this.collection.hasNextPage = function () { return true; };
            this.listView.render();
            this.listView.loadNext();
            expect(this.listView.$el.find('a.search-load-next .icon-spin')[0]).toBeVisible();
            this.listView.renderNext();
            expect(this.listView.$el.find('a.search-load-next .icon-spin')[0]).toBeHidden();
        });

    });


    describe('SearchRouter', function () {

        beforeEach(function () {
            this.router = new SearchRouter();
        });

        it ('has a search route', function () {
            expect(this.router.routes['search/:query']).toEqual('search');
        });

    });


    describe('SearchApp', function () {

        beforeEach(function () {
            TemplateHelpers.installTemplate('templates/courseware_search/search_item');
            TemplateHelpers.installTemplate('templates/courseware_search/search_list');
            TemplateHelpers.installTemplate('templates/courseware_search/search_loading');
            TemplateHelpers.installTemplate('templates/courseware_search/search_error');

            // spy on these methods before they are bound to events
            spyOn(SearchRouter.prototype, 'navigate').andCallThrough();
            spyOn(SearchForm.prototype, 'doSearch').andCallThrough();
            spyOn(SearchCollection.prototype, 'performSearch').andCallThrough();
            spyOn(SearchCollection.prototype, 'cancelSearch').andCallThrough();
            spyOn(SearchCollection.prototype, 'loadNextPage').andCallThrough();
            spyOn(SearchListView.prototype, 'showLoadingMessage').andCallThrough();
            spyOn(SearchListView.prototype, 'clear').andCallThrough();

            this.app = new SearchApp('a/b/c');

        });

        it ('has all necessary components', function () {
            expect(this.app).toBeDefined();
            expect(this.app.router).toBeDefined();
            expect(this.app.form).toBeDefined();
            expect(this.app.collection).toBeDefined();
            expect(this.app.results).toBeDefined();
        });

        it ('shows loading message on search', function () {
            this.app.form.trigger('search');
            expect(this.app.results.showLoadingMessage).toHaveBeenCalled();
        });

        it ('performs search', function () {
            this.app.form.trigger('search');
            expect(this.app.collection.performSearch).toHaveBeenCalled();
        });

        it ('updates navigation history on search', function () {
            this.app.form.trigger('search', 'search_string');
            expect(this.app.router.navigate).toHaveBeenCalledWith('search/search_string', { replace: true });
        });

        it ('cancels search', function () {
            this.app.form.trigger('clear');
            expect(this.app.collection.cancelSearch).toHaveBeenCalled();
        });

        it ('clears results', function () {
            this.app.form.trigger('clear');
            expect(this.app.results.clear).toHaveBeenCalled();
        });

        it ('updates navigation history on clear', function () {
            this.app.form.trigger('clear');
            expect(this.app.router.navigate).toHaveBeenCalledWith(/* nothing */);
        });

        it ('loads next page', function () {
            this.app.results.trigger('next');
            expect(this.app.collection.loadNextPage).toHaveBeenCalled();
        });

        it ('navigates to search', function () {
            Backbone.history.loadUrl('search/query');
            expect(this.app.form.doSearch).toHaveBeenCalledWith('query');
        });

    });

});
