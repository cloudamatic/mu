rs.status().members.forEach(function (status) {
    if (status.health === 0) {
        rs.remove(status.name);
    }
});
