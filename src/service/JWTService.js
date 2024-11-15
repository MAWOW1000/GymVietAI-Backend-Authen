import db from '../models/index';

const getRoleWithPermission = async (user) => {
    let permission = await db.Role.findOne({
        where: { id: user.roleId },
        attributes: ["id", "name", "description"],
        include: {
            model: db.Permission,
            attributes: ["id", "url", "description"],
            through: { attributes: [] }
        }
    })

    return permission ? permission : {};
}

module.exports = {
    getRoleWithPermission
}