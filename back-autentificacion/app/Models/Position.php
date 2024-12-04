<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Position extends Model
{
    protected $fillable = [
        'name',
        'priority',
    ];

    public function users()
    {
        return $this->hasMany(User::class, 'position'); // Si 'position' es la clave foránea
    }
}
