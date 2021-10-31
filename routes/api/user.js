const express = require("express");
const { User, validate } = require("../../models/User");
const bcrypt = require("bcryptjs");
const _ = require("lodash");
const auth = require("../../middleware/auth");
const router = express.Router();
const mongoose = require("mongoose");
const debug = require("debug")("app:routes");
const Joi = require("joi");
const { join, basename } = require("path");
const { moveFile, deleteFile } = require("../../utilities/fileManager");

const {
    uploadImage,
    fileUploadPaths,
} = require("../../middleware/uploadHandler");
const { Post } = require("../../models/post");

router.get("/users", async (req, res) => {
    const user = await User.find().select("-password");

    res.json(user);
});

// @route   GET api/v1/user/me
// @desc    user info
// @access  private
router.get("/me", auth, async (req, res) => {
    const user = await User.findById(req.user._id).select("-password")
    res.json(
        _.pick(user, [
            "_id",
            "name",
            "username",
            "email",
            "bio",
            "region",
            "address",
            "picture",
            "following"
        ])
    );
});

// @route   POST api/v1/user
// @desc    register user
// @access  Public
router.post("/", async (req, res) => {
    const { error } = validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const { email, password } = req.body;

    // Check if email is uesed
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ message: "User already exist" });

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    user = new User({
        ...req.body,
        password: hash,
        username: req.body.name
            .split(" ")
            .concat(Math.floor(Math.random() * 100))
            .join("."),
    });

    user = await user.save();

    const token = user.generateAuthToken();
    // .header("x-auth-token", token)
    res.status(200).json({
        token,
        user: _.pick(user, [
            "_id",
            "name",
            "username",
            "email",
            "bio",
            "region",
            "address",
            "picture",
        ]),
    });
});

// @route   GET api/v1/card
// @desc    Search for cards
// @access  public
router.get("/search", async (req, res) => {
    const { q } = req.query;
    if (!q) return res.status(400).json({ message: "no query" });

    const searchResualt = await User.find({
        name: { $regex: `(?:${q.split(' ').join('|')})`, $options: 'i' }
    });

    res.status(200).json(searchResualt);
});

// @route   GET api/v1/user/update
// @desc    update profile
// @access  private
router.patch(
    "/update",
    auth,
    uploadImage.single("picture"),
    async (req, res) => {
        const { error } = validateUser(req.body);
        if (error) return res.status(400).send(error.details[0].message);

        const user = await User.findById(req.user._id);
        let update_values = req.body;
        if (req.file) {
            let image_filename = basename(user.picture);
            const imageName = req.file.filename;
            if (imageName !== image_filename && image_filename !== "default.jpg")
                deleteFile(
                    join(fileUploadPaths.USER_IMAGE_UPLOAD_PATH, image_filename)
                );

            //set the path of the new image
            path = `${fileUploadPaths.USER_IMAGE_URL}/${imageName}`;
            update_values = { ...update_values, picture: path };
            moveFile(
                join(fileUploadPaths.FILE_UPLOAD_PATH, imageName),
                join(fileUploadPaths.USER_IMAGE_UPLOAD_PATH, imageName)
            );
        }
        debug(update_values);

        const newUser = await User.findByIdAndUpdate(
            req.user._id,
            update_values
        ).select("-password");
        debug(newUser);
        res.json({
            message: "user updated",
            success: true,
        });
    }
);

// @route   GET api/v1/user/me
// @desc    get user profile
// @access  private
router.get("/:_id", async (req, res) => {
    const user = await User.findById(req.params._id).select("-password");
    const all_posts = await Post.find({
        user_id: req.params._id,
        deleted: "false",
    }).populate("User");

    res.json({
        user: _.pick(user, [
            "_id",
            "name",
            "username",
            "email",
            "bio",
            "region",
            "address",
            "picture",
        ]),
        posts: all_posts,
    });
});

router.get("/profile/:id", async (req, res) => {
    try {
        const users = await User.aggregate([
            { $match: { _id: mongoose.Types.ObjectId(req.params.id) } },
            {
                $project: {
                    name: 1,
                    picture: 1,
                    email: 1,
                    username: 1,
                    bio: 1,
                    region: 1,
                    address: 1,
                    followers: { $size: "$followers" },
                    following: { $size: "$following" }
                }
            },
        ])
        if (!users[0]) return res.json({
            message: "User not found",
        }, 404);
        return res.json(users[0])
    } catch (error) {
        console.log(error);
        return res.status(500).json({
            message: "an error has occured",
        })
    }

});
//get a user's posts
router.get("/posts/:id", async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 0;
        const limit = parseInt(req.query.limit) || 5;
        const posts = await Post.find({
            user_id: req.params.id,
            deleted: "false",
        }).populate({
            path: "user_id",
            select: 'name picture'
        })
            .sort({ Date_creation: -1 })
            .skip(page * limit).limit(limit)
        const total = await Post.countDocuments({
            user_id: req.params.id,
            deleted: "false",
        })
        return res.json({ posts, total })
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "an error has occured" })
    }
})
//follow a user
router.post(
    "/follow/:id",
    auth, async (req, res) => {
        try {

            const loggedUser = await User.findById(req.user._id)

            if (!loggedUser.following.includes(req.params.id)) {
                loggedUser.following.push(req.params.id)
                await loggedUser.save()
                await User.updateOne({ _id: req.params.id }, { $push: { followers: req.user._id } })
                return res.status(200).json([])

            }
            else return res.status(400).json({ message: 'You are already following this user' })
        } catch (error) {
            console.log(error);
            return res.status(500).json({
                message: "an error has occured",
            })
        }

    });
//unfollow a user
router.post(
    "/unfollow/:id",
    auth, async (req, res) => {
        try {
            const followingsRemoved = await User.updateOne({ _id: req.user._id }, { $pull: { following: req.params.id } })
            if (followingsRemoved === 0) return res.status(400).json({
                message: "This user isn't in your followers",
            })
            await User.updateOne({ _id: req.params.id }, { $pull: { followers: req.user._id } })
            return res.status(200).json([])
        } catch (error) {
            console.log(error);
            return res.status(500).json({
                message: "an error has occured",
            })
        }

    });
const validateUser = (user) => {
    const schema = {
        name: Joi.string().min(5).max(50),
        bio: Joi.string().min(50),
        region: Joi.string().min(5).max(50),
        address: Joi.string().min(5).max(50),
        email: Joi.string().min(5).max(50).email(),
        // isAdmin: Joi.boolean(),
        // isPro: Joi.boolean(),
    };
    return Joi.validate(user, schema);
};
module.exports = router;
