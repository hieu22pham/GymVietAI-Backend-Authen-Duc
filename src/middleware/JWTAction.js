
require("dotenv").config();
import jwt from "jsonwebtoken";
import { getRoleWithPermission } from '../service/JWTService'
import { v4 as uuidv4 } from 'uuid';
import db from '../models/index';
import moment from "moment";

const nonSecurePaths = ['/logout', '/login', '/register', '/verify-server-token'];

const createJWT = (payload) => {
    let key = process.env.JWT_SECRET;
    let token = null;
    try {
        token = jwt.sign(payload, key, {
            expiresIn: process.env.JWT_EXPIRES_IN
        });
    } catch (err) {
        console.log(err)
    }
    return token;
}

const verifyToken = (token) => {
    let key = process.env.JWT_SECRET;
    let decoded = null;

    try {
        decoded = jwt.verify(token, key);
    } catch (err) {
        if (err.name === "TokenExpiredError") {
            return decoded = "TokenExpiredError";
        }
    }
    return decoded;
}

const extractToken = (req) => {
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
        return req.headers.authorization.split(' ')[1];
    }
    return null;
}

// const checkUserJWT = async (req, res, next) => {
//     if (nonSecurePaths.includes(req.path)) return next();
//     let cookies = req.cookies;
//     let tokenFromHeader = extractToken(req);
//     if ((cookies && cookies['access-token']) || tokenFromHeader) {
//         let token = cookies && cookies['access-token'] ? cookies['access-token'] : tokenFromHeader;
//         let decoded = verifyToken(token);
//         if (decoded && decoded !== "TokenExpiredError") {
//             decoded.access_token = cookies['access-token']
//             decoded.refresh_token = cookies['refresh-token']
//             req.user = decoded;
//             next();
//         }
//         else if (decoded && decoded === "TokenExpiredError") {
//             const refresh_token = cookies['refresh-token']
//             const data = await updateCookies(refresh_token)
//             if (data.token && data.refreshToken) {
//                 res.cookie('access-token', data.token,
//                     { maxAge: 3000000, httpOnly: true }
//                 )
//                 res.cookie('refresh-token', data.refreshToken)
//             }
//             return res.status(433).json({
//                 EC: -1,
//                 DT: '',
//                 EM: 'Not authenticated the user'
//             })
//         } else {
//             return res.status(401).json({
//                 EC: -1,
//                 DT: '',
//                 EM: 'Not authenticated the user'
//             })
//         }
//     }
//     else {
//         return res.status(401).json({
//             EC: -1,
//             DT: '',
//             EM: 'Not authenticated the user'
//         })
//     }
// }

const checkUserJWT = async (req, res, next) => {
    if (nonSecurePaths.includes(req.path)) return next();

    let cookies = req.cookies;
    let tokenFromHeader = extractToken(req);

    if (cookies?.['access-token'] || tokenFromHeader) {
        let token = cookies?.['access-token'] || tokenFromHeader;
        let decoded = verifyToken(token);

        if (decoded && decoded !== "TokenExpiredError") {
            req.user = decoded;
            req.user.access_token = cookies['access-token'];
            // req.user.refresh_token = cookies['refresh-token'];
            req.user.refresh_token = cookies['refresh-token'];

            return next();
        } 

        console.log("decoded checkUserJWT: ", decoded)
        
        if (decoded === "TokenExpiredError") {
            const refresh_token = cookies['refresh-token'];
            // const data = await updateCookies(refresh_token);
            const data = await updateCookies("123");

            if (data.token && data.refreshToken) {
                // Set cookies mới
                res.cookie('access-token', data.token, { httpOnly: true, maxAge: 60 }); // 60 giây
                // res.cookie('access-token', data.token, { httpOnly: true, maxAge: 15 * 60 * 1000 }); // 15 phút
                // res.cookie('refresh-token', data.refreshToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
                res.cookie('refresh-token', data.refreshToken, { httpOnly: true, maxAge: 30 }); // 7 giây
                 // 7 ngày
                req.user = verifyToken(data.token);
                return next();
            }

            return res.status(401).json({
                EC: -1,
                DT: '',
                EM: 'Refresh token is invalid or expired'
            });
        }

        return res.status(401).json({
            EC: -1,
            DT: '',
            EM: 'Invalid access token'
        });
    }

    return res.status(401).json({
        EC: -1,
        DT: '',
        EM: 'Not authenticated the user'
    });
};


const checkUserPermission = (req, res, next) => {
    if (nonSecurePaths.includes(req.path) || req.path === '/account') return next();
    
    if (req.user) {
        let email = req.user.email;
        let roles = req.user.groupWithRoles.Roles;

        let currentUrl = req.path;
        if (!roles || roles.length === 0) {
            return res.status(403).json({
                EC: -1,
                DT: '',
                EM: `you don't permission to access this resource...`
            })
        }

        let canAccess = roles.some(item => item.url === currentUrl || currentUrl.includes(item.url));
        if (canAccess === true) {
            next();
        } else {
            return res.status(403).json({
                EC: -1,
                DT: '',
                EM: `you don't permission to access this resource...`
            })
        }
    } else {
        return res.status(401).json({
            EC: -1,
            DT: '',
            EM: 'Not authenticated the user'
        })
    }
}

const checkVerifyServerToken = (req, res) => {
    let tokenFromHeader = extractToken(req);
    if (tokenFromHeader) {
        let token = tokenFromHeader;
        let decoded = verifyToken(token);
        if (decoded) {
            return res.status(200).json({
                EC: 0,
                DT: '',
                EM: 'Success'
            })
        } else {
            return res.status(433).json({
                EC: -1,
                DT: '',
                EM: 'Token does not valid'
            })
        }
    }
    else {
        return res.status(402).json({
            EC: -1,
            DT: '',
            EM: 'Not type token valid'
        })
    }
}

// const updateCookies = async (refresh_token) => {
//     try {
//         let user = await db.User.findOne({
//             where: { refreshToken: refresh_token }
//         })
//         if (user) {
//             let groupWithRoles = await getGroupWithRoles(user);
//             const payload = {
//                 email: user.email,
//                 username: user.username,
//                 groupWithRoles
//             }
//             const token = await createJWT(payload)
//             const refreshToken = uuidv4();
//             await user.update({
//                 refreshToken: refreshToken
//             })
//             return {
//                 token, refreshToken
//             }
//         } else {
//             //not found
//             return {
//                 EM: 'User not found',
//                 EC: 2,
//                 DT: ''
//             }
//         }
//     } catch (e) {
//         console.log(e);
//         return {
//             EM: 'something wrongs with servies',
//             EC: 1,
//             DT: []
//         }
//     }
// }

const updateCookies = async (refresh_token) => {
    try {
        let user = await db.User.findOne({ where: { refreshToken: refresh_token } });
        
        if (!user) {
            return { EM: 'User not found', EC: 2, DT: '' };
        }

        let groupWithRoles = await getRoleWithPermission(user);
        const payload = {
            email: user.email,
            username: user.username,
            groupWithRoles
        };
        
        const token = createJWT(payload);
        const refreshToken = uuidv4();

        await db.User.update({ refreshToken });

        return { token, refreshToken };

    } catch (e) {
        console.error(e); 
        return { EM: 'Something went wrong with the server', EC: 1, DT: [] };
    }
};

// 

const validateAccessToken = async (req, res, next) => {
    const cookies = req.cookies;
    const tokenFromHeader = req.headers.authorization?.split(' ')[1]; // Lấy token từ header
    const accessToken = cookies?.['access-token'] || tokenFromHeader;

    if (!accessToken) {
        return res.status(401).json({ EC: -1, EM: 'Access token is missing' });
    }

    // Giải mã access token
    const decoded = jwt.decode(accessToken);
    const refreshToken = cookies?.['refresh-token'] || accessToken;

    console.log("decoded: ", decoded)
    if (!decoded) {
        return res.status(401).json({ EC: -1, EM: 'Invalid access token' });
    }

    // Kiểm tra nếu access token đã hết hạn
    const currentTime = Math.floor(Date.now() / 1000); // Thời gian hiện tại (giây)
    console.log(currentTime)
    if (decoded.exp &&  decoded.exp - currentTime < 60) {
        if (!refreshToken) {
            return res.status(401).json({ EC: -1, EM: 'Refresh token is missing' });
        }

        try {
            // Tìm user dựa vào refresh token
            const user = await db.User.findOne({ where: { email: decoded.email } });
            console.log("User: ", user)
            console.log("refreshToken: ", refreshToken)
            if (!user) {
                return res.status(401).json({ EC: -1, EM: 'Invalid refresh token' });
            }

            // Kiểm tra thời hạn refreshTokenExpiresAt
            const currentTime = moment();
            const refreshTokenExpiresAt = moment(user.refreshTokenExpiresAt);


            console.log("refreshTokenExpiresAt - currentTime: ", refreshTokenExpiresAt - currentTime)

                console.log("Ok")
                const groupWithRoles = await getRoleWithPermission(user);
                const payload = {
                    email: user.email,
                    username: user.username,
                    groupWithRoles,
                };

                const newAccessToken = createJWT(payload); // Tạo access token mới
                const newRefreshToken = uuidv4(); // Tạo refresh token mới

                // Cập nhật refresh token vào database
                await db.User.update(
                    // { refreshToken: newRefreshToken, refreshTokenExpiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) }, // Refresh token mới, hết hạn sau 7 ngày
                    { refreshToken: newRefreshToken, refreshTokenExpiresAt: new Date(Date.now() + 60) }, // Refresh token mới, hết hạn sau 7 ngày
                    { where: { email: user.email } }
                );

                // Gửi lại access token và refresh token mới vào cookies
                // res.cookie('access-token', newAccessToken, { httpOnly: true, maxAge: 15 * 60 * 1000 }); // 15 phút
                res.cookie('access-token', newAccessToken, { httpOnly: true, maxAge: 30  }); // 30 giây
                // res.cookie('refresh-token', newRefreshToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 }); // 7 ngày
                res.cookie('refresh-token', newRefreshToken, { httpOnly: true, maxAge: 7 * 24  }); // 7*24 giây

                // Cập nhật lại user thông tin vào request
                req.user = jwt.decode(newAccessToken);

                return next(); // Tiếp tục xử lý
            // Tạo mới access token và refresh token
            
        } catch (err) {
            console.error('Error in validateAccessToken:', err);
            return res.status(500).json({ EC: -1, EM: 'Internal server error' });
        }
    }

    // Nếu access token hợp lệ
    req.user = decoded;
    return next();
};

const validatePermission = (allowedRoles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ EC: -1, EM: 'User not authenticated' });
        }

        const userRoles = req.user.groupWithRoles?.Roles || [];

        // Kiểm tra xem user có quyền phù hợp không
        const hasPermission = userRoles.some(role => allowedRoles.includes(role.url));

        if (hasPermission) {
            return next();
        }

        return res.status(403).json({ EC: -1, EM: 'You do not have permission to access this resource' });
    };
};

const checkAndRefreshToken = async (email) => {
    try {
        // Lấy thông tin user từ bảng User
        const user = await db.User.findOne({
            where: { email },
            attributes: ['refreshToken', 'refreshTokenExpiresAt'], // Lấy các trường cần thiết
            raw: true,
        });

        if (!user) {
            return {
                EC: -1,
                EM: 'User not found',
                DT: null,
            };
        }

        // Lấy thời gian hiện tại và thời gian hết hạn của refresh token
        const currentTime = moment();
        const refreshTokenExpiresAt = moment(user.refreshTokenExpiresAt);

        // Kiểm tra nếu refreshToken đã hết hạn
        if (currentTime.isAfter(refreshTokenExpiresAt)) {
            // Tạo refresh token và thời gian hết hạn mới
            const newRefreshToken = uuidv4(); // Tạo refresh token mới
            const newRefreshTokenExpiresAt = moment().add(7, 'days').format('YYYY-MM-DD HH:mm:ss'); // 7 ngày sau

            // Cập nhật lại trong cơ sở dữ liệu
            await db.User.update(
                {
                    refreshToken: newRefreshToken,
                    refreshTokenExpiresAt: newRefreshTokenExpiresAt,
                },
                { where: { email } }
            );

            // Tạo access token mới
            const payload = {
                email,
                username: user.username,
            };
            const newAccessToken = createJWT(payload);

            return {
                EC: 0,
                EM: 'New tokens generated',
                DT: {
                    accessToken: newAccessToken,
                    refreshToken: newRefreshToken,
                },
            };
        }

        // Nếu refresh token vẫn còn hạn
        return {
            EC: 1,
            EM: 'Refresh token is still valid',
            DT: null,
        };
    } catch (error) {
        console.error('Error in checkAndRefreshToken:', error);
        return {
            EC: -2,
            EM: 'Something went wrong',
            DT: null,
        };
    }
};

const refreshTokens = async (req, res) => {
    const email = req.body.email; // Giả sử email được gửi từ client
    const result = await checkAndRefreshToken(email);

    if (result.EC === 0) {
        return res.status(200).json(result);
    }
    return res.status(400).json(result);
};

module.exports = {
    createJWT, verifyToken, checkUserJWT, checkUserPermission, checkVerifyServerToken, validateAccessToken, validatePermission,
    checkAndRefreshToken
}