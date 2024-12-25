import userApiService from '../service/userApiService';
import userService from '../service/userApiService';

const readFunc = async (req, res) => {
    try {
        if (req.query.page && req.query.limit) {
            let page = parseInt(req.query.page);
            let limit = parseInt(req.query.limit);

            if (isNaN(page) || isNaN(limit) || page < 1 || limit < 1) {
                return res.status(400).json({
                    EM: 'Invalid pagination parameters',
                    EC: 1,
                    DT: null
                });
            }

            let data = await userApiService.getUsersWithPagination(page, limit);
            return res.status(200).json({
                EM: data.EM,
                EC: data.EC,
                DT: data.DT
            });
        } else {
            let data = await userApiService.getAllUsers();
            return res.status(200).json({
                EM: data.EM,
                EC: data.EC,
                DT: data.DT
            });
        }
    } catch (error) {
        console.log('Error in readFunc:', error);
        return res.status(500).json({
            EM: 'Error from server',
            EC: -1,
            DT: null
        });
    }
}

const createFunc = async (req, res) => {
    try {
        let data = req.body;

        if (!data.email || !data.password) {
            return res.status(400).json({
                EM: 'Missing required fields',
                EC: 1,
                DT: null
            });
        }

        let result = await userApiService.createNewUser(data);
        return res.status(200).json({
            EM: result.EM,
            EC: result.EC,
            DT: result.DT
        });
    } catch (error) {
        console.log('Error in createFunc:', error);
        return res.status(500).json({
            EM: 'Error from server',
            EC: -1,
            DT: null
        });
    }
}

const updateFunc = async (req, res) => {
    try {
        let data = req.body;

        if (!data.id) {
            return res.status(400).json({
                EM: 'Missing user ID',
                EC: 1,
                DT: null
            });
        }

        let result = await userApiService.updateUser(data);
        return res.status(200).json({
            EM: result.EM,
            EC: result.EC,
            DT: result.DT
        });
    } catch (error) {
        console.log('Error in updateFunc:', error);
        return res.status(500).json({
            EM: 'Error from server',
            EC: -1,
            DT: null
        });
    }
}

const deleteFunc = async (req, res) => {
    try {
        let { id } = req.body;

        if (!id) {
            return res.status(400).json({
                EM: 'Missing user ID',
                EC: 1,
                DT: null
            });
        }

        let result = await userApiService.deleteUser(id);
        return res.status(200).json({
            EM: result.EM,
            EC: result.EC,
            DT: result.DT
        });
    } catch (error) {
        console.log('Error in deleteFunc:', error);
        return res.status(500).json({
            EM: 'Error from server',
            EC: -1,
            DT: null
        });
    }
}

const addWorkoutPlanFunc = async (req, res) => {
    try {
        const email = req.user.email;
        const workoutPlanId = req.body.workout_plan_id;

        if (!email || !workoutPlanId) {
            return res.status(400).json({
                EM: 'Missing email or workout plan ID',
                EC: 1,
                DT: null
            });
        }

        const data = await userService.addWorkoutPlan(email, workoutPlanId);

        return res.status(data.EC === 0 ? 200 : 400).json({
            EM: data.EM,
            EC: data.EC,
            DT: data.DT
        });
    } catch (error) {
        console.error('Add exercise error:', error);
        return res.status(500).json({
            EM: 'Error from server',
            EC: -1,
            DT: null
        });
    }
};

const addNutritionPlanFunc = async (req, res) => {
    try {
        const email = req.user.email;
        const nutritionPlanId = req.body.nutrition_plan_id;

        if (!email || !nutritionPlanId) {
            return res.status(400).json({
                EM: 'Missing email or nutrition plan ID',
                EC: 1,
                DT: null
            });
        }

        const data = await userService.addNutritionPlan(email, nutritionPlanId);

        return res.status(data.EC === 0 ? 200 : 400).json({
            EM: data.EM,
            EC: data.EC,
            DT: data.DT
        });
    } catch (error) {
        console.error('Add meal plan error:', error);
        return res.status(500).json({
            EM: 'Error from server',
            EC: -1,
            DT: null
        });
    }
};

const getUserByEmailFunc = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({
                EM: 'Missing email in request body',
                EC: 1,
                DT: null
            });
        }

        let result = await userApiService.getUserByEmail(email);
        return res.status(200).json({
            EM: result.EM,
            EC: result.EC,
            DT: result.DT
        });
    } catch (error) {
        console.log('Error in getUserByEmailFunc:', error);
        return res.status(500).json({
            EM: 'Error from server',
            EC: -1,
            DT: null
        });
    }
}

module.exports = {
    readFunc,
    createFunc,
    updateFunc,
    deleteFunc,
    addWorkoutPlanFunc,
    addNutritionPlanFunc,
    getUserByEmailFunc
}