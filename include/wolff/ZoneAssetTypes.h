#pragma once

#include <cstddef>
#include <cstdint>

// Asset type names, one table per title - every title renumbered these (rawfile alone is 31 in
// CoD4, 32 in WaW, 36 in BO1, 41 in BO2, 47 in BO3), so a bare zone type index means nothing.
//
// Generated from Laupetin/OpenAssetTools (GPL-3.0, same as Wolff) rather than typed out,
// to avoid a silent transcription slip.

namespace wolff::ZoneAssetTypes
{
    // CallOfDuty4, 33 types
    inline const char* const CallOfDuty4[] = {
        "xmodelpieces", "physpreset", "xanimparts", "xmodel", "material", "technique_set", "image", "sound", "sound_curve", "loaded_sound", "clipmap", "clipmap_pvs", "comworld", "gameworld_sp", "gameworld_mp", "map_ents", "gfxworld", "light_def", "ui_map", "font", "menulist", "menu", "localize_entry", "weapon", "snddriver_globals", "fx", "impact_fx", "aitype", "mptype", "character", "xmodelalias", "rawfile", "stringtable"
    };

    // WorldAtWar, 35 types
    inline const char* const WorldAtWar[] = {
        "xmodelpieces", "physpreset", "physconstraints", "destructibledef", "xanimparts", "xmodel", "material", "technique_set", "image", "sound", "loaded_sound", "clipmap", "clipmap_pvs", "comworld", "gameworld_sp", "gameworld_mp", "map_ents", "gfxworld", "light_def", "ui_map", "font", "menulist", "menu", "localize_entry", "weapon", "snddriver_globals", "fx", "impact_fx", "aitype", "mptype", "character", "xmodelalias", "rawfile", "stringtable", "pack_index"
    };

    // BlackOps, 43 types
    inline const char* const BlackOps[] = {
        "xmodelpieces", "physpreset", "physconstraints", "destructibledef", "xanimparts", "xmodel", "material", "technique_set", "image", "sound", "sound_patch", "clipmap", "clipmap_pvs", "comworld", "gameworld_sp", "gameworld_mp", "map_ents", "gfxworld", "light_def", "ui_map", "font", "menulist", "menu", "localize_entry", "weapon", "weapondef", "weapon_variant", "snddriver_globals", "fx", "impact_fx", "aitype", "mptype", "mpbody", "mphead", "character", "xmodelalias", "rawfile", "stringtable", "pack_index", "xglobals", "ddl", "glasses", "emblemset"
    };

    // BlackOps2, 60 types
    inline const char* const BlackOps2[] = {
        "xmodelpieces", "physpreset", "physconstraints", "destructibledef", "xanimparts", "xmodel", "material", "technique_set", "image", "sound", "sound_patch", "clipmap", "clipmap_pvs", "comworld", "gameworld_sp", "gameworld_mp", "map_ents", "gfxworld", "light_def", "ui_map", "font", "fonticon", "menulist", "menu", "localize_entry", "weapon", "weapondef", "weapon_variant", "weapon_full", "attachment", "attachment_unique", "weapon_camo", "snddriver_globals", "fx", "impact_fx", "aitype", "mptype", "mpbody", "mphead", "character", "xmodelalias", "rawfile", "stringtable", "leaderboard", "xglobals", "ddl", "glasses", "emblemset", "scriptparsetree", "keyvaluepairs", "vehicledef", "memoryblock", "addon_map_ents", "tracer", "skinnedverts", "qdb", "slug", "footstep_table", "footstepfx_table", "zbarrier"
    };

    // BlackOps3, 103 types. From joseupp/t7x rather than OpenAssetTools,
    // which stops at Black Ops 2.
    inline const char* const BlackOps3[] = {
        "physpreset", "physconstraints", "destructibledef", "xanimparts", "xmodel", "xmodelmesh", "material", "compute_shader_set", "technique_set", "image", "sound", "sound_patch", "clipmap", "comworld", "gameworld", "map_ents", "gfxworld", "light_def", "lensflare_def", "ui_map", "font", "fonticon", "localize_entry", "weapon", "weapondef", "weapon_variant", "weapon_full", "cgmedia", "playersounds", "playerfx", "sharedweaponsounds", "attachment", "attachment_unique", "weapon_camo", "customization_table", "customization_table_fe_images", "customization_table_color", "snddriver_globals", "fx", "tagfx", "new_lensflare_def", "impact_fx", "impact_sound", "player_character", "aitype", "character", "xmodelalias", "rawfile", "stringtable", "structured_table", "leaderboard", "ddl", "glasses", "texturelist", "scriptparsetree", "keyvaluepairs", "vehicledef", "addon_map_ents", "tracer", "slug", "surfacefx_table", "surfacesounddef", "footstep_table", "entityfximpacts", "entitysoundimpacts", "zbarrier", "vehiclefxdef", "vehiclesounddef", "typeinfo", "scriptbundle", "scriptbundlelist", "rumble", "bulletpenetration", "locdmgtable", "aimtable", "animselectortableset", "animmappingtable", "animstatemachine", "behaviortree", "behaviorstatemachine", "ttf", "sanim", "light_description", "shellshock", "xcam", "bg_cache", "texture_combo", "flametable", "bitfield", "attachment_cosmetic_variant", "maptable", "maptable_loading_images", "medal", "medaltable", "objective", "objective_list", "umbra_tome", "navmesh", "navvolume", "binaryhtml", "laser", "beam", "streamer_hint"
    };

    // Hands back a name, or nullptr when the id is past the end of that title's list
    inline const char* Lookup(const char* const* Table, size_t Count, uint32_t Type)
    {
        return (Table != nullptr && Type < Count) ? Table[Type] : nullptr;
    }
}
