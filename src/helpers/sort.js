module.exports = function sortable(field, sort) {
    const sortType = field === sort.field ? sort.type : 'default';
    const icons = {
        default: 'bi bi-funnel',
        desc: 'bi bi-sort-down',
        asc: 'bi bi-sort-up-alt',
    };

    const types = {
        default: 'asc',
        asc: 'desc',
        desc: 'asc',
    };

    return `<a href="?_sort&field=${field}&type=${types[sortType]}">
            <i class="${icons[sortType]}"></i>
        </a>`;
};
