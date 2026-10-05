export function authorizeModification(req, res, next) {
    const userId = Number(req.params.userId);

    if (req.user.role === "parent") {
        return next();
    }

    if (req.user.role === "child" && req.user.id === userId) {
        return next();
    }

    return res.status(403).json({ error: "Access denied" });
}